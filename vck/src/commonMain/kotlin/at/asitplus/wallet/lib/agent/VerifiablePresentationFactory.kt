package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.TransactionData
import at.asitplus.openid.dcql.DCQLClaimsQueryResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.openid.third_party.at.asitplus.jsonpath.core.plus
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.SdJwtCreator.NAME_SD
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.DeviceAuth
import at.asitplus.wallet.lib.iso.DeviceNameSpaces
import at.asitplus.wallet.lib.iso.DeviceResponse
import at.asitplus.wallet.lib.iso.DeviceSigned
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.SdJwtSigned
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.datetime.Clock
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class VerifiablePresentationFactory(
    private val jwsService: JwsService,
    private val coseService: CoseService,
    private val identifier: String,
) {
    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry,
        disclosedAttributes: Collection<NormalizedJsonPath>,
    ): KmmResult<CreatePresentationResult> = catching {
        when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> createVcPresentation(
                request = request,
                validCredentials = listOf(credential.vcSerialized),
            )

            is SubjectCredentialStore.StoreEntry.SdJwt -> createSdJwtPresentation(
                request = request,
                validSdJwtCredential = credential,
                requestedClaims = disclosedAttributes,
            )

            is SubjectCredentialStore.StoreEntry.Iso -> createIsoPresentation(
                request = request,
                credential = credential,
                requestedClaims = disclosedAttributes,
            )
        }
    }

    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry,
        disclosedAttributes: DCQLCredentialQueryMatchingResult,
    ): KmmResult<CreatePresentationResult> = catching {
        when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> if (disclosedAttributes !is DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult) {
                throw IllegalArgumentException("Credential type only allows disclosure of all attributes.")
            } else createVcPresentation(
                request = request,
                validCredentials = listOf(credential.vcSerialized),
            )

            is SubjectCredentialStore.StoreEntry.SdJwt -> createSdJwtPresentation(
                request = request,
                validSdJwtCredential = credential,
                requestedClaims = when (disclosedAttributes) {
                    DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult -> credential.disclosures.entries.map {
                        NormalizedJsonPath() + it.value!!.claimName!!
                    }

                    is DCQLCredentialQueryMatchingResult.ClaimsQueryResults -> disclosedAttributes.claimsQueryResults.map {
                        it as DCQLClaimsQueryResult.JsonResult
                    }.map {
                        it.nodeList.map {
                            it.normalizedJsonPath
                        }
                    }.flatten()
                },
            )

            is SubjectCredentialStore.StoreEntry.Iso -> createIsoPresentation(
                request = request,
                credential = credential,
                requestedClaims = when (disclosedAttributes) {
                    DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult -> credential.issuerSigned.namespaces!!.entries.flatMap { namespace ->
                        namespace.value.entries.map {
                            NormalizedJsonPath() + namespace.key + it.value.elementIdentifier
                        }
                    }

                    is DCQLCredentialQueryMatchingResult.ClaimsQueryResults -> disclosedAttributes.claimsQueryResults.map {
                        it as DCQLClaimsQueryResult.IsoMdocResult
                    }.map {
                        NormalizedJsonPath() + it.namespace + it.claimName
                    }
                },
            )
        }
    }

    private suspend fun createIsoPresentation(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry.Iso,
        requestedClaims: Collection<NormalizedJsonPath>,
    ): CreatePresentationResult.DeviceResponse {
        Napier.d("createIsoPresentation with $request and $requestedClaims for $credential")

        // allows disclosure of attributes from different namespaces
        val namespaceToAttributesMap = requestedClaims.mapNotNull { normalizedJsonPath ->
            // namespace + attribute
            val firstTwoNameSegments = normalizedJsonPath.segments.filterIndexed { index, _ ->
                // TODO: unsure how to deal with attributes with a depth of more than 2
                //  revealing the whole attribute for now, which is as fine grained as MDOC can do anyway
                index < 2
            }.filterIsInstance<NormalizedJsonPathSegment.NameSegment>()
            if (firstTwoNameSegments.size == 2) {
                val namespace = firstTwoNameSegments[0].memberName
                val attributeName = firstTwoNameSegments[1].memberName
                namespace to attributeName
            } else {
                // TODO: Not a namespaced attribute, how to deal with these?
                //  treating them as fields that are inherent to the credential for now
                //  -> no need for selective disclosure
                null
            }
        }.groupBy {
            it.first  // grouping by namespace
        }.mapValues {
            // unrolling values to just the list of attribute names for that namespace
            it.value.map { it.second }
        }
        val disclosedItems = namespaceToAttributesMap.mapValues { namespaceToAttributeNamesEntry ->
            val namespace = namespaceToAttributeNamesEntry.key
            val attributeNames = namespaceToAttributeNamesEntry.value
            attributeNames.map { attributeName ->
                credential.issuerSigned.namespaces?.get(
                    namespace
                )?.entries?.find {
                    it.value.elementIdentifier == attributeName
                }?.value
                    ?: throw PresentationException("Attribute not available in credential: $['$namespace']['$attributeName']")
            }
        }
        val docType = credential.scheme?.isoDocType!!
        val deviceNameSpaceBytes = ByteStringWrapper(DeviceNameSpaces(mapOf()))
        val (deviceSignature, mDocGeneratedNonce) = request.calcIsoDeviceSignature.invoke(docType)
            ?: throw PresentationException("CalculateChallengeResponse not implemented")
        return CreatePresentationResult.DeviceResponse(
            deviceResponse = DeviceResponse(
                version = "1.0",
                documents = arrayOf(
                    Document(
                        docType = docType,
                        issuerSigned = IssuerSigned.fromIssuerSignedItems(
                            namespacedItems = disclosedItems,
                            issuerAuth = credential.issuerSigned.issuerAuth
                        ),
                        deviceSigned = DeviceSigned(
                            namespaces = deviceNameSpaceBytes,
                            deviceAuth = DeviceAuth(
                                deviceSignature = deviceSignature
                            )
                        )
                    )
                ),
                status = 0U,
            ),
            mdocGeneratedNonce = mDocGeneratedNonce
        )
    }

    private suspend fun createSdJwtPresentation(
        request: PresentationRequestParameters,
        validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
        requestedClaims: Collection<NormalizedJsonPath>,
    ): CreatePresentationResult.SdJwt {
        // TODO: this feels wrong, each path should represent a single attribute to be disclosed
        val nameSegments = requestedClaims
            .flatMap { it.segments }
            .filterIsInstance<NormalizedJsonPathSegment.NameSegment>()
        // All disclosures as requested by claim name
        val disclosuresByName = nameSegments
            .mapNotNull { claim ->
                validSdJwtCredential.disclosures.entries.firstOrNull { it.value?.claimName == claim.memberName }
            }.toSet()
        // Inner disclosures when an object has been requested by name (above), but contains more _sd entries
        val innerDisclosures = validSdJwtCredential.disclosures.entries.filter { claim ->
            claim.asHashedDisclosure()?.let { hashedDisclosure ->
                disclosuresByName.any { it.containsHashedDisclosure(hashedDisclosure) }
            } == true
        }
        val allDisclosures = (disclosuresByName.map { it.key } + innerDisclosures.map { it.key }).toSet()

        val issuerJwtPlusDisclosures = SdJwtSigned.sdHashInput(validSdJwtCredential, allDisclosures)
        val keyBinding = createKeyBindingJws(request, issuerJwtPlusDisclosures)
        val issuerSignedJwsSerialized = validSdJwtCredential.vcSerialized.substringBefore("~")
        val issuerSignedJws =
            JwsSigned.deserialize<JsonElement>(JsonElement.serializer(), issuerSignedJwsSerialized, vckJsonSerializer)
                .getOrElse {
                    Napier.w("Could not re-create JWS from stored SD-JWT", it)
                    throw PresentationException(it)
                }
        val sdJwt = SdJwtSigned.serializePresentation(issuerSignedJws, allDisclosures, keyBinding)
        return CreatePresentationResult.SdJwt(sdJwt)
    }

    private fun Map.Entry<String, SelectiveDisclosureItem?>.asHashedDisclosure(): String? =
        value?.toDisclosure()?.hashDisclosure()

    private fun Map.Entry<String, SelectiveDisclosureItem?>.containsHashedDisclosure(hashDisclosure: String): Boolean =
        asJsonObject()?.sdElements()?.strings()?.any { it == hashDisclosure } == true

    private fun Map.Entry<String, SelectiveDisclosureItem?>.asJsonObject(): JsonObject? =
        (value?.claimValue as? JsonObject?)

    private fun JsonObject.sdElements(): JsonArray? = (get(NAME_SD) as? JsonArray?)

    private fun JsonArray.strings(): List<String>? = mapNotNull { (it as? JsonPrimitive?)?.content }

    private suspend fun createKeyBindingJws(
        request: PresentationRequestParameters,
        issuerJwtPlusDisclosures: String,
    ): JwsSigned<KeyBindingJws> = jwsService.createSignedJwsAddingParams(
        header = JwsHeader(
            type = JwsContentTypeConstants.KB_JWT,
            algorithm = jwsService.algorithm,
        ),
        payload = KeyBindingJws(
            issuedAt = Clock.System.now(),
            audience = request.audience,
            challenge = request.nonce,
            sdHash = issuerJwtPlusDisclosures.encodeToByteArray().sha256(),
            transactionData = request.transactionData,
            transactionDataHashes = request.getTransactionDataHashes(),
            transactionDataHashesAlgorithm = request.transactionData?.let { "sha-256" }
        ),
        serializer = KeyBindingJws.serializer(),
        addKeyId = false,
        addJsonWebKey = false,
        addX5c = false,
    ).getOrElse {
        Napier.w("Could not create JWS for presentation", it)
        throw PresentationException(it)
    }

    /**
     * Creates a [VerifiablePresentation] with the given [validCredentials].
     *
     * Note: The caller is responsible that only valid credentials are passed to this function!
     */
    suspend fun createVcPresentation(
        validCredentials: List<String>,
        request: PresentationRequestParameters,
    ) = CreatePresentationResult.Signed(
        jwsService.createSignedJwt(
            type = JwsContentTypeConstants.JWT,
            payload = VerifiablePresentation(validCredentials)
                .toJws(request.nonce, identifier, request.audience),
            serializer = VerifiablePresentationJws.serializer(),
        ).getOrElse {
            Napier.w("Could not create JWS for presentation", it)
            throw PresentationException(it)
        }.serialize()
    )
}
