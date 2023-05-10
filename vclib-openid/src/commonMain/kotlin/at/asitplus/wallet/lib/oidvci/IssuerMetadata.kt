package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * To be serialized into `/.well-known/openid-credential-issuer`
 */
@Serializable
data class IssuerMetadata(
    @SerialName("issuer")
    val issuer: String,

    @SerialName("credential_issuer")
    val credentialIssuer: String,

    @SerialName("authorization_server")
    val authorizationServer: String? = null,

    @SerialName("credential_endpoint")
    val credentialEndpointUrl: String,

    @SerialName("token_endpoint")
    val tokenEndpointUrl: String,

    @SerialName("authorization_endpoint")
    val authorizationEndpointUrl: String,

    @SerialName("batch_credential_endpoint")
    val batchCredentialEndpointUrl: String? = null,

    @SerialName("credentials_supported")
    val supportedCredentialFormat: Array<SupportedCredentialFormat>,

    @SerialName("display")
    val displayProperties: Array<DisplayProperties>? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IssuerMetadata

        if (issuer != other.issuer) return false
        if (credentialIssuer != other.credentialIssuer) return false
        if (authorizationServer != other.authorizationServer) return false
        if (credentialEndpointUrl != other.credentialEndpointUrl) return false
        if (tokenEndpointUrl != other.tokenEndpointUrl) return false
        if (authorizationEndpointUrl != other.authorizationEndpointUrl) return false
        if (batchCredentialEndpointUrl != other.batchCredentialEndpointUrl) return false
        if (!supportedCredentialFormat.contentEquals(other.supportedCredentialFormat)) return false
        if (displayProperties != null) {
            if (other.displayProperties == null) return false
            if (!displayProperties.contentEquals(other.displayProperties)) return false
        } else if (other.displayProperties != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issuer.hashCode()
        result = 31 * result + credentialIssuer.hashCode()
        result = 31 * result + (authorizationServer?.hashCode() ?: 0)
        result = 31 * result + credentialEndpointUrl.hashCode()
        result = 31 * result + tokenEndpointUrl.hashCode()
        result = 31 * result + authorizationEndpointUrl.hashCode()
        result = 31 * result + (batchCredentialEndpointUrl?.hashCode() ?: 0)
        result = 31 * result + supportedCredentialFormat.contentHashCode()
        result = 31 * result + (displayProperties?.contentHashCode() ?: 0)
        return result
    }
}