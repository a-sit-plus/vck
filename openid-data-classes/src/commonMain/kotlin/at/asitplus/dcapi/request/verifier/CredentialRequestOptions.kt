package at.asitplus.dcapi.request.verifier

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialRequestOptions(
    @SerialName("digital")
    val digital: DigitalCredentialRequestOptions
)
