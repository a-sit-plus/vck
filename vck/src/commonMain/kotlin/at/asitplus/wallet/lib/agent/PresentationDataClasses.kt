package at.asitplus.wallet.lib.agent

import at.asitplus.dif.ConstraintField
import at.asitplus.dif.PresentationSubmission
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.core.NormalizedJsonPath
import kotlinx.serialization.Serializable

data class PresentationResponseParameters(
    val presentationSubmission: PresentationSubmission,
    val presentationResults: List<CreatePresentationResult>
)

sealed class CreatePresentationResult {
    /**
     * [jws] contains a valid, serialized, Verifiable Presentation that can be parsed by [Verifier.verifyPresentation]
     */
    data class Signed(val jws: String) : CreatePresentationResult()

    /**
     * [sdJwt] contains a serialized SD-JWT credential with disclosures and key binding JWT appended
     * (separated with `~` as in the specification), that can be parsed by [Verifier.verifyPresentation].
     */
    data class SdJwt(val sdJwt: String) : CreatePresentationResult()

    /**
     * [deviceResponse] contains a valid ISO 18013 [DeviceResponse] with [Document] and [DeviceSigned] structures
     */
    data class DeviceResponse(val deviceResponse: at.asitplus.wallet.lib.iso.DeviceResponse) :
        CreatePresentationResult()
}

@Serializable
data class CredentialSubmission(
    val credential: SubjectCredentialStore.StoreEntry,
    val disclosedAttributes: Collection<NormalizedJsonPath>,
)

typealias InputDescriptorMatches = Map<SubjectCredentialStore.StoreEntry, Map<ConstraintField, NodeList>>

fun Map<String, Map<SubjectCredentialStore.StoreEntry, Map<ConstraintField, NodeList>>>.toDefaultSubmission() =
    mapNotNull { descriptorCredentialMatches ->
        descriptorCredentialMatches.value.entries.firstNotNullOfOrNull { credentialConstraintFieldMatches ->
            CredentialSubmission(
                credential = credentialConstraintFieldMatches.key,
                disclosedAttributes = credentialConstraintFieldMatches.value.values.mapNotNull {
                    it.firstOrNull()?.normalizedJsonPath
                },
            )
        }?.let {
            descriptorCredentialMatches.key to it
        }
    }.toMap()


/**
 * Implementations should return true, when the credential attribute may be disclosed to the verifier.
 */
typealias PathAuthorizationValidator = (credential: SubjectCredentialStore.StoreEntry, attributePath: NormalizedJsonPath) -> Boolean

open class PresentationException : Exception {
    constructor(message: String) : super(message)
    constructor(throwable: Throwable) : super(throwable)
}