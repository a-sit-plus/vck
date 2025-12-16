package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.sha256
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.ClaimsQueryResults
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.SdJwtConstants.NAME_SD
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.extensions.sdHashInput
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.Clock

class VerifiablePresentationFactory(
    private val keyMaterial: KeyMaterial,
    private val signVerifiablePresentation: SignJwtFun<VerifiablePresentationJws> =
        SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    private val signKeyBinding: SignJwtFun<KeyBindingJws> =
        SignJwt(keyMaterial, JwsHeaderNone()),
) {

    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credentialAndDisclosedAttributes: Map<SubjectCredentialStore.StoreEntry.Iso, Collection<NormalizedJsonPath>>,
    ): KmmResult<CreatePresentationResult> = catching {
        CreatePresentationResult.DeviceResponse.build(
            request = request,
            credentialsAndMeta = credentialAndDisclosedAttributes.mapValues { IsoPresentationMeta(it.value) },
        )
    }

    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry,
        disclosedAttributes: Collection<NormalizedJsonPath>,
    ): KmmResult<CreatePresentationResult> = catching {
        when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> createVcPresentation(
                request = request,
                validCredentials = listOf(credential),
            )

            is SubjectCredentialStore.StoreEntry.SdJwt -> createSdJwtPresentation(
                request = request,
                validSdJwtCredential = credential,
                requestedClaims = disclosedAttributes,
            )

            is SubjectCredentialStore.StoreEntry.Iso -> CreatePresentationResult.DeviceResponse.build(
                request = request,
                credentialsAndMeta = mapOf(credential to IsoPresentationMeta(disclosedAttributes)),
            )
        }
    }

    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry,
        disclosedAttributes: DCQLCredentialQueryMatchingResult,
        systemSpec: SystemSpec? = null,
    ): KmmResult<CreatePresentationResult> = catching {
        when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> if (disclosedAttributes !is AllClaimsMatchingResult) {
                throw IllegalArgumentException("Credential type only allows disclosure of all attributes.")
            } else createVcPresentation(
                request = request,
                validCredentials = listOf(credential),
            )

            is SubjectCredentialStore.StoreEntry.SdJwt -> createSdJwtPresentation(
                request = request,
                validSdJwtCredential = credential,
                requestedClaims = when (disclosedAttributes) {
                    AllClaimsMatchingResult -> credential.disclosures.entries.map {
                        NormalizedJsonPath() + it.value!!.claimName!!
                    }

                    is ClaimsQueryResults -> disclosedAttributes.claimsQueryResults.map {
                        it as DCQLClaimsQueryResult.JsonResult
                    }.map {
                        it.nodeList.map {
                            it.normalizedJsonPath
                        }
                    }.flatten()
                },
            )

            is SubjectCredentialStore.StoreEntry.Iso -> {
                val requestedClaims = disclosedAttributes.toRequestedIsoClaims(credential)
                val spec = systemSpec ?: SystemSpec.Default
                // Since we are in the DCQL flow there is only 1 single credential, so we can just directly map here
                val credentialAndMeta = mapOf(
                    credential to IsoPresentationMeta(requestedClaims, spec),
                )
                CreatePresentationResult.DeviceResponse.build(
                    request = request,
                    credentialsAndMeta = credentialAndMeta,
                )
            }
        }
    }

    private fun DCQLCredentialQueryMatchingResult.toRequestedIsoClaims(
        credential: SubjectCredentialStore.StoreEntry.Iso,
    ) = when (this) {
        AllClaimsMatchingResult -> credential.issuerSigned.namespaces!!.entries.flatMap { namespace ->
            namespace.value.entries.map {
                NormalizedJsonPath() + namespace.key + it.value.elementIdentifier
            }
        }

        is ClaimsQueryResults -> claimsQueryResults.map {
            it as DCQLClaimsQueryResult.IsoMdocResult
        }.map {
            NormalizedJsonPath() + it.namespace + it.claimName
        }
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
            val digest = validSdJwtCredential.sdJwt.selectiveDisclosureAlgorithm?.toDigest() ?: Digest.SHA256
            claim.asHashedDisclosure(digest)?.let { hashedDisclosure ->
                disclosuresByName.any { it.containsHashedDisclosure(hashedDisclosure) }
            } == true
        }
        val allDisclosures = (disclosuresByName.map { it.key } + innerDisclosures.map { it.key }).toSet()

        val issuerJwtPlusDisclosures = SdJwtSigned.sdHashInput(validSdJwtCredential, allDisclosures)
        val keyBinding = createKeyBindingJws(request, issuerJwtPlusDisclosures)
        val issuerSignedJwsSerialized = validSdJwtCredential.vcSerialized.substringBefore("~")
        val issuerSignedJws =
            JwsSigned.deserialize(JsonElement.serializer(), issuerSignedJwsSerialized, vckJsonSerializer)
                .getOrElse { throw PresentationException(it) }
        val sdJwt = SdJwtSigned.presented(issuerSignedJws, allDisclosures, keyBinding)
        return CreatePresentationResult.SdJwt(sdJwt.serialize(), sdJwt)
    }

    private fun Map.Entry<String, SelectiveDisclosureItem?>.asHashedDisclosure(digest: Digest): String? =
        value?.toDisclosure()?.hashDisclosure(digest)

    private fun Map.Entry<String, SelectiveDisclosureItem?>.containsHashedDisclosure(hashDisclosure: String): Boolean =
        asJsonObject()?.sdElements()?.strings()?.any { it == hashDisclosure } == true

    private fun Map.Entry<String, SelectiveDisclosureItem?>.asJsonObject(): JsonObject? =
        (value?.claimValue as? JsonObject?)

    private fun JsonObject.sdElements(): JsonArray? = (get(NAME_SD) as? JsonArray?)

    private fun JsonArray.strings(): List<String> = mapNotNull { (it as? JsonPrimitive?)?.content }

    private suspend fun createKeyBindingJws(
        request: PresentationRequestParameters,
        issuerJwtPlusDisclosures: String,
    ): JwsSigned<KeyBindingJws> = signKeyBinding(
        JwsContentTypeConstants.KB_JWT,
        KeyBindingJws(
            issuedAt = Clock.System.now().truncateToSeconds(),
            audience = request.audience,
            challenge = request.nonce,
            sdHash = issuerJwtPlusDisclosures.encodeToByteArray().sha256(),
            transactionDataHashes = request.transactionData?.hash(request.transactionDataHashesAlgorithm),
            transactionDataHashesAlgorithmString = request.transactionDataHashesAlgorithm?.toIanaName(),
        ),
        KeyBindingJws.serializer(),
    ).getOrElse {
        throw PresentationException(it)
    }

    /**
     * Creates a [VerifiablePresentation] with the given [validCredentials].
     *
     * Note: The caller is responsible that only valid credentials are passed to this function!
     */
    suspend fun createVcPresentation(
        validCredentials: List<SubjectCredentialStore.StoreEntry.Vc>,
        request: PresentationRequestParameters,
    ): CreatePresentationResult.Signed = with(
        signVerifiablePresentation(
            JwsContentTypeConstants.JWT,
            VerifiablePresentation(validCredentials.map { it.vcSerialized }).toJws(
                request.nonce,
                validCredentials.map { it.vc.vc.credentialSubject.id }.first(),
                request.audience
            ),
            VerifiablePresentationJws.serializer(),
        ).getOrElse {
            throw PresentationException(it)
        }) {
        CreatePresentationResult.Signed(serialize(), this)
    }
}
