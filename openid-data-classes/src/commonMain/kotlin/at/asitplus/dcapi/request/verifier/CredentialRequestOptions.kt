package at.asitplus.dcapi.request.verifier

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@ConsistentCopyVisibility
@Serializable
data class CredentialRequestOptions @Deprecated("Default constructor has been replaced with create() method", ReplaceWith("CredentialRequestOptions.create(requests)")) private constructor(
    @SerialName("mediation")
    val mediation: String,
    @SerialName("digital")
    val digital: DigitalCredentialRequestOptions,
) {
    @Suppress("DEPRECATION")
    companion object {
        fun create(requests: List<DigitalCredentialGetRequest>): CredentialRequestOptions =
            CredentialRequestOptions(
                mediation = MEDIATION_REQUIRED,
                digital = DigitalCredentialRequestOptions(requests)
            )

        private const val MEDIATION_REQUIRED = "required"
    }
}
