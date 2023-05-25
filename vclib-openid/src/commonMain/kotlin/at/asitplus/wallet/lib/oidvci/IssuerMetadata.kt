package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * To be serialized into `/.well-known/openid-credential-issuer`
 */
@Serializable
data class IssuerMetadata(
    /**
     * OIDC Discovery: REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as
     * its Issuer Identifier. If Issuer discovery is supported (see Section 2), this value MUST be identical to the
     * issuer value returned by WebFinger. This also MUST be identical to the `iss` Claim value in ID Tokens issued
     * from this Issuer.
     */
    @SerialName("issuer")
    val issuer: String,

    /**
     * OID4VCI: REQUIRED. The Credential Issuer's identifier.
     */
    @SerialName("credential_issuer")
    val credentialIssuer: String,

    /**
     * OID4VCI: OPTIONAL. Identifier of the OAuth 2.0 Authorization Server (as defined in RFC8414) the Credential
     * Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is
     * also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain
     * the Authorization Server metadata as per RFC8414.
     */
    @SerialName("authorization_server")
    val authorizationServer: String? = null,

    /**
     * OID4VCI: REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and
     * MAY contain port, path and query parameter components.
     */
    @SerialName("credential_endpoint")
    val credentialEndpointUrl: String,

    /**
     * OIDC Discovery: URL of the OP's OAuth 2.0 Token Endpoint (OpenID.Core). This is REQUIRED unless only the
     * Implicit Flow is used.
     */
    @SerialName("token_endpoint")
    val tokenEndpointUrl: String,

    /**
     * OIDC Discovery: REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint (OpenID.Core).
     */
    @SerialName("authorization_endpoint")
    val authorizationEndpointUrl: String,

    /**
     * OID4VCI: OPTIONAL. URL of the Credential Issuer's Batch Credential Endpoint. This URL MUST use the https scheme
     * and MAY contain port, path and query parameter components. If omitted, the Credential Issuer does not support
     * the Batch Credential Endpoint.
     */
    @SerialName("batch_credential_endpoint")
    val batchCredentialEndpointUrl: String? = null,

    /**
     * OID4VCI: REQUIRED. A JSON array containing a list of JSON objects, each of them representing metadata about a
     * separate credential type that the Credential Issuer can issue. The JSON objects in the array MUST conform to the
     * structure of the Section 10.2.3.1.
     */
    @SerialName("credentials_supported")
    val supportedCredentialFormat: Array<SupportedCredentialFormat>,

    /**
     * OID4VCI: OPTIONAL. An array of objects, where each object contains display properties of a Credential Issuer for
     * a certain language.
     */
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