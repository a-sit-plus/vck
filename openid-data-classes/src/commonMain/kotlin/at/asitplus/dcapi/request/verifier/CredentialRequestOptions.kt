package at.asitplus.dcapi.request.verifier

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@ConsistentCopyVisibility
@Serializable
data class CredentialRequestOptions private constructor(
    @SerialName("mediation")
    val mediation: String,
    @SerialName("digital")
    val digital: DigitalCredentialRequestOptions,
) {
    companion object {
        fun create(requests: List<DigitalCredentialGetRequest>): CredentialRequestOptions =
            CredentialRequestOptions(
                mediation = MEDIATION_REQUIRED,
                digital = DigitalCredentialRequestOptions(requests)
            )

        private const val MEDIATION_REQUIRED = "required"
    }
}
