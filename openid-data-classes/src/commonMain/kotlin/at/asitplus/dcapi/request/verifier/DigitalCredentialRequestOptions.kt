package at.asitplus.dcapi.request.verifier

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DigitalCredentialRequestOptions(
    @SerialName("requests")
    val requests: List<DigitalCredentialGetRequest>,
)
