package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.PresentationSubmission
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.SdJwtSigned
import kotlinx.serialization.Serializable

data class PresentationRequestParameters(
    val nonce: String,
    val audience: String,
)

data class PresentationResponseParameters(
    val presentationSubmission: PresentationSubmission,
    val presentationResults: List<CreatePresentationResult>
)

sealed class CreatePresentationResult {
    data class Signed(val serialized: String) : CreatePresentationResult() {
        val jwsSigned: KmmResult<JwsSigned<VerifiablePresentationJws>> by lazy {
            JwsSigned.deserialize(VerifiablePresentationJws.serializer(), serialized, vckJsonSerializer)
        }
    }

    data class SdJwt(val serialized: String) : CreatePresentationResult() {
        val sdJwt: SdJwtSigned? by lazy { SdJwtSigned.parse(serialized) }
    }

    data class DeviceResponse(
        val deviceResponse: at.asitplus.wallet.lib.iso.DeviceResponse,
    ) : CreatePresentationResult()
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
