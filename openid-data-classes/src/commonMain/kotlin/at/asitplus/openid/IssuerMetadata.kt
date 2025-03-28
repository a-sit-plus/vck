package at.asitplus.openid

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Metadata about the credential issuer in
 * [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 *
 * To be serialized into `/.well-known/openid-credential-issuer`.
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
    val issuer: String? = null,

    /**
     * OID4VCI: REQUIRED. The Credential Issuer's identifier, by a case sensitive URL using the `https`
     * scheme that contains scheme, host and, optionally, port number and path components, but no query
     * or fragment components
     */
    @SerialName("credential_issuer")
    val credentialIssuer: String,

    /**
     * OID4VCI: OPTIONAL. Array of strings, where each string is an identifier of the OAuth 2.0 Authorization Server
     * (as defined in RFC8414) the Credential Issuer relies on for authorization. If this parameter is omitted, the
     * entity providing the Credential Issuer is also acting as the Authorization Server, i.e., the Credential Issuer's
     * identifier is used to obtain the Authorization Server metadata.
     */
    @SerialName("authorization_servers")
    val authorizationServers: Set<String>? = null,

    /**
     * OID4VCI: REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and
     * MAY contain port, path and query parameter components.
     */
    @SerialName("credential_endpoint")
    val credentialEndpointUrl: String,

    /**
     * OID4VCI: OPTIONAL. URL of the Credential Issuer's Nonce Endpoint, as defined in Section 7.
     * This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
     * If omitted, the Credential Issuer does not support the Nonce Endpoint.
     */
    @SerialName("nonce_endpoint")
    val nonceEndpointUrl: String? = null,

    /**
     * OID4VCI: OPTIONAL. URL of the Credential Issuer's Deferred Credential Endpoint, as defined in Section 8.
     * This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components.
     * If omitted, the Credential Issuer does not support the Deferred Credential Endpoint.
     */
    @SerialName("deferred_credential_endpoint")
    val deferredCredentialEndpointUrl: String? = null,

    /**
     * OID4VCI: OPTIONAL. URL of the Credential Issuer's Notification Endpoint, as defined in Section 10.
     * This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components.
     * If omitted, the Credential Issuer does not support the Notification Endpoint.
     */
    @SerialName("notification_endpoint")
    val notificationEndpointUrl: String? = null,

    /**
     * OID4VCI: OPTIONAL. Object containing information about whether the Credential Issuer supports encryption of the
     * Credential and Batch Credential Response on top of TLS.
     */
    @SerialName("credential_response_encryption")
    val credentialResponseEncryption: SupportedAlgorithmsContainer? = null,

    /**
     * OID4VCI: OPTIONAL. Object containing information about the Credential Issuer's supports for batch issuance of
     * Credentials on the Credential Endpoint. The presence of this parameter means that the issuer supports the proofs
     * parameter in the Credential Request so can issue more than one Verifiable Credential for the same Credential
     * Dataset in a single request/response.
     */
    @SerialName("batch_credential_issuance")
    val batchCredentialIssuance: BatchCredentialIssuanceMetadata? = null,

    /**
     * OPTIONAL. String that is a signed JWT. This JWT contains Credential Issuer metadata parameters as claims. The
     * signed metadata MUST be secured using JSON Web Signature (JWS) (`RFC7515`) and MUST contain an `iat` (Issued At)
     * claim, an `iss` (Issuer) claim denoting the party attesting to the claims in the signed metadata, and `sub`
     * (Subject) claim matching the Credential Issuer identifier. If the Wallet supports signed metadata, metadata
     * values conveyed in the signed JWT MUST take precedence over the corresponding values conveyed using plain JSON
     * elements. If the Credential Issuer wants to enforce use of signed metadata, it omits the respective metadata
     * parameters from the unsigned part of the Credential Issuer metadata. A [signedMetadata] metadata value MUST NOT
     * appear as a claim in the JWT. The Wallet MUST establish trust in the signer of the metadata, and obtain the keys
     * to validate the signature before processing the metadata. The concrete mechanism how to do that is out of scope
     * of this specification and MAY be defined in the profiles of this specification.
     */
    // TODO Analyze usage
    @SerialName("signed_metadata")
    val signedMetadata: String? = null,

    /**
     * OID4VCI: OPTIONAL. An array of objects, where each object contains display properties of a Credential Issuer for
     * a certain language.
     */
    @SerialName("display")
    val displayProperties: Set<DisplayProperties>? = null,

    /**
     * OID4VCI: REQUIRED. Object that describes specifics of the Credential that the Credential Issuer supports
     * issuance of. This object contains a list of name/value pairs, where each name is a unique identifier of the
     * supported Credential being described. This identifier is used in the Credential Offer as defined in
     * Section 4.1.1 to communicate to the Wallet which Credential is being offered, see [CredentialOffer].
     */
    @SerialName("credential_configurations_supported")
    val supportedCredentialConfigurations: Map<String, SupportedCredentialFormat>? = null,
) {
    fun serialize() = odcJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<IssuerMetadata> =
            runCatching { odcJsonSerializer.decodeFromString<IssuerMetadata>(input) }.wrap()
    }
}