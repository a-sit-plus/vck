package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * This implements RFC8414 `https://www.rfc-editor.org/rfc/rfc8414.html`
 * All descriptions taken from section 2.
 *
 * To be serialized into `/.well-known/oauth-authorization-server`
 * which is the registered default-path
 * (see `https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml`)
 */

@Serializable
data class OAuth2AuthorizationServerMetadata(
    /**
     * REQUIRED.  The authorization server's issuer identifier, which is
     * a URL that uses the "https" scheme and has no query or fragment
     * components.  Authorization server metadata is published at a
     * location that is ".well-known" according to `RFC5785`
     * derived from this issuer identifier, as described in Section 3.
     * The issuer identifier is used to prevent authorization server mix-up
     * attacks, as described in "OAuth 2.0 Mix-Up Mitigation"
     * `MIX-UP`.
     */
    @SerialName("issuer")
    val issuer: String,

    /**
     * URL of the authorization server's authorization endpoint
     * `RFC6749`.  This is REQUIRED unless no grant types are supported
     * that use the authorization endpoint.
     *
     * NOTE: Mandatory for our use-case
     */
    @SerialName("authorization_endpoint")
    val authorizationEndpoint: String,

    /**
     * URL of the authorization server's token endpoint `RFC6749`.  This
     * is REQUIRED unless only the implicit grant type is supported.
     *
     * NOTE: Mandatory for our use-case
     */
    @SerialName("token_endpoint")
    val tokenEndpoint: String,

    /**
     * OPTIONAL.  URL of the authorization server's JWK Set `JWK`
     * document.  The referenced document contains the signing key(s) the
     * client uses to validate signatures from the authorization server.
     * This URL MUST use the "https" scheme.  The JWK Set MAY also
     * contain the server's encryption key or keys, which are used by
     * clients to encrypt requests to the server.  When both signing and
     * encryption keys are made available, a "use" (public key use)
     * parameter value is REQUIRED for all keys in the referenced JWK Set
     * to indicate each key's intended usage.
     */
    @SerialName("jwks_uri")
    val jwksUri: String? = null,

    /**
     * OPTIONAL.  URL of the authorization server's OAuth 2.0 Dynamic
     * Client Registration endpoint `RFC7591`.
     */
    @SerialName("registration_endpoint")
    val registrationEndpoint: String? = null,

    /**
     * RECOMMENDED.  JSON array containing a list of the OAuth 2.0
     * `RFC6749` "scope" values that this authorization server supports.
     * Servers MAY choose not to advertise some supported scope values
     * even when this parameter is used.
     */
    @SerialName("scope_supported")
    val scopesSupported: List<String>? = null,

    /**
     * REQUIRED.  JSON array containing a list of the OAuth 2.0
     * "response_type" values that this authorization server supports.
     * The array values used are the same as those used with the
     * "response_types" parameter defined by "OAuth 2.0 Dynamic Client
     * Registration Protocol" `RFC7591`.
     */
    @SerialName("response_types_supported")
    val responseTypesSupported: List<String>? = null,

    /**
     * OPTIONAL.  JSON array containing a list of the OAuth 2.0
     * "response_mode" values that this authorization server supports, as
     * specified in "OAuth 2.0 Multiple Response Type Encoding Practices"
     * `OAuth.Responses`.  If omitted, the default is "["query",
     * "fragment"]".  The response mode value "form_post" is also defined
     * in "OAuth 2.0 Form Post Response Mode" `OAuth.Post`.
     */
    @SerialName("response_modes_supported")
    val responseModesSupported: List<String>? = null,

    /**
     * OPTIONAL.  JSON array containing a list of the OAuth 2.0 grant
     * type values that this authorization server supports.  The array
     * values used are the same as those used with the "grant_types"
     * parameter defined by "OAuth 2.0 Dynamic Client Registration
     * Protocol" `RFC7591`.  If omitted, the default value is
     * "["authorization_code", "implicit"]".
     */
    @SerialName("grant_types_supported")
    val grantTypesSupported: List<String>? = null,

    /**
     * OPTIONAL.  JSON array containing a list of client authentication
     * methods supported by this token endpoint.  Client authentication
     * method values are used in the "token_endpoint_auth_method"
     * parameter defined in Section 2 of `RFC7591`.  If omitted, the
     * default is "client_secret_basic" -- the HTTP Basic Authentication
     * Scheme specified in Section 2.3.1 of OAuth 2.0 `RFC6749`.
     */
    @SerialName("token_endpoint_auth_methods_supported")
    val tokenEndPointAuthMethodsSupported: List<String>? = null,

    /**
     * OPTIONAL.  JSON array containing a list of the JWS signing
     * algorithms ("alg" values) supported by the token endpoint for the
     * signature on the JWT `JWT` used to authenticate the client at the
     * token endpoint for the "private_key_jwt" and "client_secret_jwt"
     * authentication methods.  This metadata entry MUST be present if
     * either of these authentication methods are specified in the
     * "token_endpoint_auth_methods_supported" entry.  No default
     * algorithms are implied if this entry is omitted.  Servers SHOULD
     * support "RS256".  The value "none" MUST NOT be used.
     */
    @SerialName("token_endpoint_auth_signing_alg_methods_supported")
    val tokenEndPointAuthSigningAlgValuesSupported: List<String>? = null,

    /**
     * OPTIONAL.  URL of a page containing human-readable information
     * that developers might want or need to know when using the
     * authorization server.  In particular, if the authorization server
     * does not support Dynamic Client Registration, then information on
     * how to register clients needs to be provided in this
     * documentation.
     */
    @SerialName("service_documentation")
    val serviceDocumentation: String? = null,

    /**
     * OPTIONAL.  Languages and scripts supported for the user interface,
     * represented as a JSON array of language tag values from BCP 47
     * `RFC5646`.  If omitted, the set of supported languages and scripts
     * is unspecified.
     */
    @SerialName("ui_locales_supported")
    val uiLocalesSupported: List<String>? = null,

    /**
     * OPTIONAL.  URL that the authorization server provides to the
     * person registering the client to read about the authorization
     * server's requirements on how the client can use the data provided
     * by the authorization server.  The registration process SHOULD
     * display this URL to the person registering the client if it is
     * given.  As described in Section 5, despite the identifier
     * "op_policy_uri" appearing to be OpenID-specific, its usage in this
     * specification is actually referring to a general OAuth 2.0 feature
     * that is not specific to OpenID Connect.
     */
    @SerialName("op_policy_uri")
    val opPolicyUri: String? = null,

    /**
     * OPTIONAL.  URL that the authorization server provides to the
     * person registering the client to read about the authorization
     * server's terms of service.  The registration process SHOULD
     * display this URL to the person registering the client if it is
     * given.  As described in Section 5, despite the identifier
     * "op_tos_uri", appearing to be OpenID-specific, its usage in this
     * specification is actually referring to a general OAuth 2.0 feature
     * that is not specific to OpenID Connect.
     */
    @SerialName("op_tos_uri")
    val opTosUri: String? = null,

    /**
     * OPTIONAL.  URL of the authorization server's OAuth 2.0 revocation
     * endpoint `RFC7009`.
     */
    @SerialName("revocation_endpoint")
    val revocationEndpoint: String? = null,

    /**
     * OPTIONAL.  JSON array containing a list of client authentication
     * methods supported by this revocation endpoint.  The valid client
     * authentication method values are those registered in the IANA
     * "OAuth Token Endpoint Authentication Methods" registry
     * `IANA.OAuth.Parameters`.  If omitted, the default is
     * "client_secret_basic" -- the HTTP Basic Authentication Scheme
     * specified in Section 2.3.1 of OAuth 2.0 `RFC6749`.
     */
    @SerialName("revocation_endpoint_auth_methods_supported")
    val revocationEndpointAuthMethodsSupported: List<String>? = null,

    /**
     * OPTIONAL.  JSON array containing a list of the JWS signing
     * algorithms ("alg" values) supported by the revocation endpoint for
     * the signature on the JWT `JWT` used to authenticate the client at
     * the revocation endpoint for the "private_key_jwt" and
     * "client_secret_jwt" authentication methods.  This metadata entry
     * MUST be present if either of these authentication methods are
     * specified in the "revocation_endpoint_auth_methods_supported"
     * entry.  No default algorithms are implied if this entry is
     * omitted.  The value "none" MUST NOT be used.
     */
    @SerialName("revocation_endpoint_auth_signing_alg_values_supported")
    val revocationEndpointAuthSigningAlgValuesSupported: List<String>? = null,

    /**
     * OPTIONAL.  URL of the authorization server's OAuth 2.0
     * introspection endpoint `RFC7662`.
     */
    @SerialName("introspection_endpoint")
    val introspectionEndpoint: String? = null,

    /**
     * OPTIONAL.  JSON array containing a list of client authentication
     * methods supported by this introspection endpoint.  The valid
     * client authentication method values are those registered in the
     * IANA "OAuth Token Endpoint Authentication Methods" registry
     * `IANA.OAuth.Parameters` or those registered in the IANA "OAuth
     * Access Token Types" registry `IANA.OAuth.Parameters`.  (These
     * values are and will remain distinct, due to Section 7.2.)  If
     * omitted, the set of supported authentication methods MUST be
     * determined by other means.
     */
    @SerialName("introspection_endpoint_auth_methods_supported")
    val introspectionEndpointAuthMethodsSupported: List<String>? = null,

    /**
     * OPTIONAL.  JSON array containing a list of the JWS signing
     * algorithms ("alg" values) supported by the introspection endpoint
     * for the signature on the JWT `JWT` used to authenticate the client
     * at the introspection endpoint for the "private_key_jwt" and
     * "client_secret_jwt" authentication methods.  This metadata entry
     * MUST be present if either of these authentication methods are
     * specified in the "introspection_endpoint_auth_methods_supported"
     * entry.  No default algorithms are implied if this entry is
     * omitted.  The value "none" MUST NOT be used.
     */
    @SerialName("introspection_endpoint_auth_signing_alg_values_supported")
    val introspectionEndpointAuthSigningAlgValuesSupported: List<String>? = null,

    /**
     * OPTIONAL.  JSON array containing a list of Proof Key for Code
     * Exchange (PKCE) `RFC7636` code challenge methods supported by this
     * authorization server.  Code challenge method values are used in
     * the "code_challenge_method" parameter defined in Section 4.3 of
     * `RFC7636`.  The valid code challenge method values are those
     * registered in the IANA "PKCE Code Challenge Methods" registry
     * `IANA.OAuth.Parameters`.  If omitted, the authorization server
     * does not support PKCE.
     */
    @SerialName("code_challenge_methods_supported")
    val codeChallengeMethodsSupported: List<String>? = null,
) {
    fun serialize() = at.asitplus.wallet.lib.oidc.jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<IssuerMetadata> =
            runCatching { at.asitplus.wallet.lib.oidc.jsonSerializer.decodeFromString<IssuerMetadata>(input) }.wrap()
    }
}
