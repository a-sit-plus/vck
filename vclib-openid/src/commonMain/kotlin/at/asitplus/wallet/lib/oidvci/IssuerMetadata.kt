package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.jws.JwsAlgorithm
import at.asitplus.wallet.lib.oidc.IdTokenType
import at.asitplus.wallet.lib.oidc.jsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

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
    val issuer: String? = null,

    /**
     * OID4VCI: REQUIRED. The Credential Issuer's identifier.
     */
    @SerialName("credential_issuer")
    val credentialIssuer: String? = null,

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
    val credentialEndpointUrl: String? = null,

    /**
     * OIDC Discovery: URL of the OP's OAuth 2.0 Token Endpoint (OpenID.Core). This is REQUIRED unless only the
     * Implicit Flow is used.
     */
    @SerialName("token_endpoint")
    val tokenEndpointUrl: String? = null,

    /**
     * OIDC Discovery: REQUIRED. URL of the OP's JSON Web Key Set document. This contains the signing key(s) the RP
     * uses to validate signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are
     * used by RPs to encrypt requests to the Server.
     *
     * OIDC SIOPv2: MUST NOT be present in Self-Issued OP Metadata. If it is, the RP MUST ignore it and use the `sub`
     * Claim in the ID Token to obtain signing keys to validate the signatures from the Self-Issued OpenID Provider.
     */
    @SerialName("jwks_uri")
    val jsonWebKeySetUrl: String? = null,

    /**
     * OIDC Discovery: REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint (OpenID.Core).
     *
     * OIDC SIOPv2: REQUIRED. URL of the Self-Issued OP used by the RP to perform Authentication of the End-User.
     * Can be custom URI scheme, or Universal Links/App links.
     */
    @SerialName("authorization_endpoint")
    val authorizationEndpointUrl: String? = null,

    /**
     * OID4VCI: OPTIONAL. URL of the Credential Issuer's Batch Credential Endpoint, as defined in Section 8.
     * This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components.
     * If omitted, the Credential Issuer does not support the Batch Credential Endpoint.
     */
    @SerialName("batch_credential_endpoint")
    val batchCredentialEndpointUrl: String? = null,

    /**
     * OID4VCI: OPTIONAL. URL of the Credential Issuer's Deferred Credential Endpoint, as defined in Section 9.
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
     * OID4VCI: OPTIONAL. Boolean value specifying whether the Credential Issuer supports returning
     * [AuthorizationDetails.credentialIdentifiers] in the Token Response parameter, with `true`
     * indicating support. If omitted, the default value is `false`.
     */
    @SerialName("credential_identifiers_supported")
    val supportsCredentialIdentifiers: Boolean? = false,

    /**
     * OID4VCI: REQUIRED. Object that describes specifics of the Credential that the Credential Issuer supports
     * issuance of. This object contains a list of name/value pairs, where each name is a unique identifier of the
     * supported Credential being described.
     */
    @SerialName("credential_configurations_supported")
    val supportedCredentialConfigurations: Map<String, SupportedCredentialFormat>? = null,

    /**
     * OID4VCI: OPTIONAL. An array of objects, where each object contains display properties of a Credential Issuer for
     * a certain language.
     */
    @SerialName("display")
    val displayProperties: Set<DisplayProperties>? = null,

    /**
     * OIDC Discovery: REQUIRED. JSON array containing a list of the OAuth 2.0 `response_type` values that this OP
     * supports. Dynamic OpenID Providers MUST support the `code`, `id_token`, and the `token id_token` Response Type
     * values.
     * OIDC SIOPv2: MUST be `id_token`.
     */
    @SerialName("response_types_supported")
    val responseTypesSupported: Set<String>? = null,

    /**
     * OIDC SIOPv2: REQUIRED. A JSON array of strings representing supported scopes.
     * MUST support the `openid` scope value.
     */
    @SerialName("scopes_supported")
    val scopesSupported: Set<String>? = null,

    /**
     * OIDC Discovery: REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports.
     * Valid types include `pairwise` and `public`.
     */
    @SerialName("subject_types_supported")
    val subjectTypesSupported: Set<String>? = null,

    /**
     * OIDC Discovery: REQUIRED. A JSON array containing a list of the JWS signing algorithms (`alg` values) supported
     * by the OP for the ID Token to encode the Claims in a JWT (RFC7519).
     * Valid values include `RS256`, `ES256`, `ES256K`, and `EdDSA`.
     */
    @SerialName("id_token_signing_alg_values_supported")
    val idTokenSigningAlgorithmsSupported: Set<JwsAlgorithm>? = null,

    /**
     * OIDC SIOPv2: REQUIRED. A JSON array containing a list of the JWS signing algorithms (alg values) supported by the
     * OP for Request Objects, which are described in Section 6.1 of OpenID.Core.
     * Valid values include `none`, `RS256`, `ES256`, `ES256K`, and `EdDSA`.
     */
    @SerialName("request_object_signing_alg_values_supported")
    val requestObjectSigningAlgorithmsSupported: Set<JwsAlgorithm>? = null,

    /**
     * OIDC SIOPv2: REQUIRED. A JSON array of strings representing URI scheme identifiers and optionally method names of
     * supported Subject Syntax Types.
     * Valid values include `urn:ietf:params:oauth:jwk-thumbprint`, `did:example` and others.
     */
    @SerialName("subject_syntax_types_supported")
    val subjectSyntaxTypesSupported: Set<String>? = null,

    /**
     * OIDC SIOPv2: OPTIONAL. A JSON array of strings containing the list of ID Token types supported by the OP,
     * the default value is `attester_signed_id_token` (the id token is issued by the party operating the OP, i.e. this
     * is the classical id token as defined in OpenID.Core), may also include `subject_signed_id_token` (Self-Issued
     * ID Token, i.e. the id token is signed with key material under the end-user's control).
     */
    @SerialName("id_token_types_supported")
    val idTokenTypesSupported: Set<IdTokenType>? = null,

    /**
     * OID4VP: OPTIONAL. Boolean value specifying whether the Wallet supports the transfer of `presentation_definition`
     * by reference, with true indicating support. If omitted, the default value is true.
     */
    @SerialName("presentation_definition_uri_supported")
    val presentationDefinitionUriSupported: Boolean = true,

    /**
     * OID4VP: REQUIRED. An object containing a list of key value pairs, where the key is a string identifying a
     * Credential format supported by the Wallet. Valid Credential format identifier values are defined in Annex E
     * of OpenID.VCI. Other values may be used when defined in the profiles of this specification.
     */
    @SerialName("vp_formats_supported")
    val vpFormatsSupported: VpFormatsSupported? = null,

    /**
     * OID4VP: OPTIONAL. Array of JSON Strings containing the values of the Client Identifier schemes that the Wallet
     * supports. The values defined by this specification are `pre-registered`, `redirect_uri`, `entity_id`, `did`.
     * If omitted, the default value is pre-registered.
     */
    @SerialName("client_id_schemes_supported")
    val clientIdSchemesSupported: Set<String>? = null,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<IssuerMetadata> =
            runCatching { jsonSerializer.decodeFromString<IssuerMetadata>(input) }.wrap()
    }
}