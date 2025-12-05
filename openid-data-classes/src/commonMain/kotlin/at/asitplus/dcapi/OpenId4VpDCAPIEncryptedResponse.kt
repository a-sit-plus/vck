package at.asitplus.dcapi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class OpenId4VpDCAPIEncryptedResponse(
    @SerialName("response")
    val response: String,
)