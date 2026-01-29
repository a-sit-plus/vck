package at.asitplus.dcapi.issuance

import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DigitalCredentialCreateRequestData(
    @SerialName("authorization_server_metadata")
    val authorizationServerMetadata: OAuth2AuthorizationServerMetadata,
)
