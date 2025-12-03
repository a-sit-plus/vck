package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JsonWebAlgorithm
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * This implements [RFC8414](https://datatracker.ietf.org/doc/html/rfc8414)
 * All descriptions taken from section 2.
 *
 * To be serialized into `/.well-known/oauth-authorization-server`
 * which is the registered default-path, see
 * [IANA](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml)
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
     * OIDC SIOPv2: REQUIRED. URL of the Self-Issued OP used by the RP to perform Authentication of the End-User.
     * Can be custom URI scheme, or Universal Links/App links.
     */
    @SerialName("authorization_endpoint")
    val authorizationEndpoint: String? = null,

    /**
     * OIDC: The UserInfo Endpoint is an OAuth 2.0 Protected Resource that returns Claims about the authenticated
     * End-User. To obtain the requested Claims about the End-User, the Client makes a request to the UserInfo Endpoint
     * using an Access Token obtained through OpenID Connect Authentication. These Claims are normally represented by a
     * JSON object that contains a collection of name and value pairs for the Claims.
     */
    @SerialName("userinfo_endpoint")
    val userInfoEndpoint: String? = null,

    /**
     * RFC 9126: The URL of the pushed authorization request endpoint at which a client can post an authorization
     * request to exchange for a request_uri value usable at the authorization server.
     *
     * See [RFC9126](https://datatracker.ietf.org/doc/html/rfc9126)
     */
    @SerialName("pushed_authorization_request_endpoint")
    val pushedAuthorizationRequestEndpoint: String? = null,

    /**
     * RFC 9126: Boolean parameter indicating whether the authorization server accepts authorization request data
     * only via PAR. If omitted, the default value is false.
     *
     * See [RFC9126](https://datatracker.ietf.org/doc/html/rfc9126)
     */
    @SerialName("require_pushed_authorization_requests")
    val requirePushedAuthorizationRequests: Boolean? = null,

    /**
     * URL of the authorization server's token endpoint `RFC6749`.  This
     * is REQUIRED unless only the implicit grant type is supported.
     */
    @SerialName("token_endpoint")
    val tokenEndpoint: String? = null,

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
     *
     * OIDC SIOPv2: MUST NOT be present in Self-Issued OP Metadata. If it is, the RP MUST ignore it and use the `sub`
     * Claim in the ID Token to obtain signing keys to validate the signatures from the Self-Issued OpenID Provider.
     */
    @SerialName("jwks_uri")
    val jsonWebKeySetUrl: String? = null,

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
     *
     * OIDC SIOPv2: REQUIRED. A JSON array of strings representing supported scopes.
     * MUST support the `openid` scope value.
     */
    @SerialName("scopes_supported")
    val scopesSupported: Set<String>? = null,

    /**
     * REQUIRED.  JSON array containing a list of the OAuth 2.0
     * "response_type" values that this authorization server supports.
     * The array values used are the same as those used with the
     * "response_types" parameter defined by "OAuth 2.0 Dynamic Client
     * Registration Protocol" `RFC7591`.
     *
     * OIDC SIOPv2: MUST be `id_token`.
     */
    @SerialName("response_types_supported")
    val responseTypesSupported: Set<String>? = null,

    /**
     * OPTIONAL.  JSON array containing a list of the OAuth 2.0
     * "response_mode" values that this authorization server supports, as
     * specified in "OAuth 2.0 Multiple Response Type Encoding Practices"
     * `OAuth.Responses`.  If omitted, the default is "["query",
     * "fragment"]".  The response mode value "form_post" is also defined
     * in "OAuth 2.0 Form Post Response Mode" `OAuth.Post`.
     */
    @SerialName("response_modes_supported")
    val responseModesSupported: Set<String>? = null,

    /**
     * OPTIONAL.  JSON array containing a list of the OAuth 2.0 grant
     * type values that this authorization server supports.  The array
     * values used are the same as those used with the "grant_types"
     * parameter defined by "OAuth 2.0 Dynamic Client Registration
     * Protocol" `RFC7591`.  If omitted, the default value is
     * "["authorization_code", "implicit"]".
     */
    @SerialName("grant_types_supported")
    val grantTypesSupported: Set<String>? = null,

    /**
     * OPTIONAL.  JSON array containing a list of client authentication
     * methods supported by this token endpoint.  Client authentication
     * method values are used in the "token_endpoint_auth_method"
     * parameter defined in Section 2 of `RFC7591`.  If omitted, the
     * default is "client_secret_basic" -- the HTTP Basic Authentication
     * Scheme specified in Section 2.3.1 of OAuth 2.0 `RFC6749`.
     */
    @SerialName("token_endpoint_auth_methods_supported")
    val tokenEndPointAuthMethodsSupported: Set<String>? = null,

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
    val tokenEndPointAuthSigningAlgValuesSupported: Set<String>? = null,

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
    val idTokenSigningAlgorithmsSupportedStrings: Set<String>? = null,

    /**
     * OIDC SIOPv2: REQUIRED. A JSON array containing a list of the JWS signing algorithms (alg values) supported by the
     * OP for Request Objects, which are described in Section 6.1 of OpenID.Core.
     * Valid values include `none`, `RS256`, `ES256`, `ES256K`, and `EdDSA`.
     */
    @SerialName("request_object_signing_alg_values_supported")
    val requestObjectSigningAlgorithmsSupportedStrings: Set<String>? = null,

    /**
     * RFC 9101: Indicates where authorization request needs to be protected as Request Object and provided through
     * either `request` or `request_uri` parameter.
     *
     * See [RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101#section-9.2)
     */
    @SerialName("require_signed_request_object")
    val requireSignedRequestObject: Boolean? = null,

    /**
     * OIDC SIOPv2: REQUIRED. A JSON array of strings representing URI scheme identifiers and optionally method names of
     * supported Subject Syntax Types.
     * Valid values include `urn:ietf:params:oauth:jwk-thumbprint`, `did:example` and others.
     */
    @SerialName("subject_syntax_types_supported")
    // TODO Verify usage of "jwk", maybe remove did
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

    @Deprecated("Removed in OpenID4VP 1.0", ReplaceWith("clientIdPrefixesSupported"))
    @SerialName("client_id_schemes_supported")
    val clientIdSchemesSupported: Set<String>? = null,

    /**
     * OID4VP: OPTIONAL. A non-empty array of strings containing the values of the Client Identifier Prefixes that the
     * Wallet supports. The values defined by this specification are `pre-registered` (which represents the behavior
     * when no Client Identifier Prefix is used), `redirect_uri`, `openid_federation`, `verifier_attestation`,
     * `decentralized_identifier`, `x509_san_dns` and `x509_hash`.
     * If omitted, the default value is `pre-registered`.
     * Other values may be used when defined in the profiles or extensions of this specification.
     */
    @SerialName("client_id_prefixes_supported")
    val clientIdPrefixesSupported: Set<String>? = null,

    /**
     * RFC 9449: A JSON array containing a list of the JWS alg values (from the `IANA.JOSE.ALGS` registry) supported
     * by the authorization server for DPoP proof JWTs.
     */
    @SerialName("dpop_signing_alg_values_supported")
    val dpopSigningAlgValuesSupportedStrings: Set<String>? = null,

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
    val uiLocalesSupported: Set<String>? = null,

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
    val revocationEndpointAuthMethodsSupported: Set<String>? = null,

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
    val revocationEndpointAuthSigningAlgValuesSupported: Set<String>? = null,

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
    val introspectionEndpointAuthMethodsSupported: Set<String>? = null,

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
    val introspectionEndpointAuthSigningAlgValuesSupported: Set<String>? = null,

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
    val codeChallengeMethodsSupported: Set<String>? = null,
) {

    /**
     * OIDC Discovery: REQUIRED. A JSON array containing a list of the JWS signing algorithms (`alg` values) supported
     * by the OP for the ID Token to encode the Claims in a JWT (RFC7519).
     * Valid values include `RS256`, `ES256`, `ES256K`, and `EdDSA`.
     */
    @Transient
    val idTokenSigningAlgorithmsSupported: Set<JwsAlgorithm>? = idTokenSigningAlgorithmsSupportedStrings
        ?.mapNotNull { it.toJwsAlgorithm() }?.toSet()

    /**
     * OIDC SIOPv2: REQUIRED. A JSON array containing a list of the JWS signing algorithms (alg values) supported by the
     * OP for Request Objects, which are described in Section 6.1 of OpenID.Core.
     * Valid values include `none`, `RS256`, `ES256`, `ES256K`, and `EdDSA`.
     */
    @Transient
    val requestObjectSigningAlgorithmsSupported: Set<JwsAlgorithm>? = requestObjectSigningAlgorithmsSupportedStrings
        ?.mapNotNull { it.toJwsAlgorithm() }?.toSet()

    /**
     * RFC 9449: A JSON array containing a list of the JWS alg values (from the `IANA.JOSE.ALGS` registry) supported
     * by the authorization server for DPoP proof JWTs.
     */
    @Transient
    val dpopSigningAlgValuesSupported: Set<JsonWebAlgorithm>? = dpopSigningAlgValuesSupportedStrings
        ?.mapNotNull { s -> JsonWebAlgorithm.entries.firstOrNull { it.identifier == s } }?.toSet()
}
