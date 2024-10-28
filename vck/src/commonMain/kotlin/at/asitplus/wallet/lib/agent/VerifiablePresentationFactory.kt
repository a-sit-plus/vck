package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.iso.*
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.SdJwtSigned
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock

class VerifiablePresentationFactory(
    private val jwsService: JwsService,
    private val coseService: CoseService,
    private val identifier: String,
) {
    suspend fun createVerifiablePresentation(
        challenge: String,
        audienceId: String,
        credential: SubjectCredentialStore.StoreEntry,
        disclosedAttributes: Collection<NormalizedJsonPath>,
    ): KmmResult<Holder.CreatePresentationResult> = runCatching {
        when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> createVcPresentation(
                challenge = challenge,
                audienceId = audienceId,
                validCredentials = listOf(credential.vcSerialized),
            )

            is SubjectCredentialStore.StoreEntry.SdJwt -> createSdJwtPresentation(
                challenge = challenge,
                audienceId = audienceId,
                validSdJwtCredential = credential,
                requestedClaims = disclosedAttributes,
            )

            is SubjectCredentialStore.StoreEntry.Iso -> createIsoPresentation(
                challenge = challenge,
                credential = credential,
                requestedClaims = disclosedAttributes,
            )
        }
    }.wrap()

    private suspend fun createIsoPresentation(
        challenge: String,
        credential: SubjectCredentialStore.StoreEntry.Iso,
        requestedClaims: Collection<NormalizedJsonPath>
    ): Holder.CreatePresentationResult.DeviceResponse {
        val deviceSignature = coseService.createSignedCose(
            payload = challenge.encodeToByteArray(), addKeyId = false
        ).getOrElse {
            Napier.w("Could not create DeviceAuth for presentation", it)
            throw PresentationException(it)
        }

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
        return Holder.CreatePresentationResult.DeviceResponse(
            DeviceResponse(
                version = "1.0",
                documents = arrayOf(
                    Document(
                        docType = credential.scheme.isoDocType!!,
                        issuerSigned = IssuerSigned.fromIssuerSignedItems(
                            namespacedItems = disclosedItems,
                            issuerAuth = credential.issuerSigned.issuerAuth
                        ),
                        deviceSigned = DeviceSigned(
                            namespaces = ByteStringWrapper(DeviceNameSpaces(mapOf())),
                            deviceAuth = DeviceAuth(
                                deviceSignature = deviceSignature
                            )
                        )
                    )
                ),
                status = 0U,
            )
        )
    }

    private suspend fun createSdJwtPresentation(
        audienceId: String,
        challenge: String,
        validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
        requestedClaims: Collection<NormalizedJsonPath>,
    ): Holder.CreatePresentationResult.SdJwt {
        val filteredDisclosures = requestedClaims
            .flatMap { it.segments }
            .filterIsInstance<NormalizedJsonPathSegment.NameSegment>()
            .mapNotNull { claim ->
                validSdJwtCredential.disclosures.entries.firstOrNull { it.value?.claimName == claim.memberName }?.key
            }.toSet()

        val issuerJwtPlusDisclosures = SdJwtSigned.sdHashInput(validSdJwtCredential, filteredDisclosures)
        val keyBinding = createKeyBindingJws(audienceId, challenge, issuerJwtPlusDisclosures)
        val jwsFromIssuer = JwsSigned.deserialize(validSdJwtCredential.vcSerialized.substringBefore("~")).getOrElse {
            Napier.w("Could not re-create JWS from stored SD-JWT", it)
            throw PresentationException(it)
        }
        val sdJwt = SdJwtSigned.serializePresentation(jwsFromIssuer, filteredDisclosures, keyBinding)
        return Holder.CreatePresentationResult.SdJwt(sdJwt)
    }

    private suspend fun createKeyBindingJws(
        audienceId: String,
        challenge: String,
        issuerJwtPlusDisclosures: String,
    ): JwsSigned = jwsService.createSignedJwsAddingParams(
        header = JwsHeader(
            type = JwsContentTypeConstants.KB_JWT,
            algorithm = jwsService.algorithm,
        ),
        payload = KeyBindingJws(
            issuedAt = Clock.System.now(),
            audience = audienceId,
            challenge = challenge,
            sdHash = issuerJwtPlusDisclosures.encodeToByteArray().sha256(),
        ).serialize().encodeToByteArray(),
        addKeyId = false,
        addJsonWebKey = true,
        addX5c = false,
    ).getOrElse {
        Napier.w("Could not create JWS for presentation", it)
        throw PresentationException(it)
    }

    private fun Map.Entry<String, SelectiveDisclosureItem?>.discloseItem(requestedClaims: Collection<String>?) =
        if (requestedClaims == null) {
            false // do not disclose by default
        } else {
            value?.let { it.claimName in requestedClaims } ?: false
        }

    /**
     * Creates a [VerifiablePresentation] with the given [validCredentials].
     *
     * Note: The caller is responsible that only valid credentials are passed to this function!
     */
    suspend fun createVcPresentation(
        validCredentials: List<String>,
        challenge: String,
        audienceId: String,
    ): Holder.CreatePresentationResult = Holder.CreatePresentationResult.Signed(
        jwsService.createSignedJwt(
            type = JwsContentTypeConstants.JWT,
            payload = VerifiablePresentation(validCredentials)
                .toJws(challenge, identifier, audienceId)
                .serialize()
                .encodeToByteArray()
        ).getOrElse {
            Napier.w("Could not create JWS for presentation", it)
            throw PresentationException(it)
        }.serialize()
    )
}
