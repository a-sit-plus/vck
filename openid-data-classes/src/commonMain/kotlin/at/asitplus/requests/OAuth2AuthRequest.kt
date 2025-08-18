package at.asitplus.requests

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ClientIdScheme
import at.asitplus.openid.OpenIdConstants.ClientIdScheme.RedirectUri
import kotlinx.serialization.SerialName

sealed interface OAuth2AuthRequest : AuthenticationRequest {
    /**
     * OAuth2: Required
     * OIDC: REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server.
     *
     * DC API: The client_id parameter MUST be omitted in unsigned requests defined in Appendix
     * A.3.1. The Wallet MUST ignore any client_id parameter that is present in an unsigned request.
     * The client_id parameter MUST be present in signed requests defined in Appendix A.3.2,
     * as it communicates to the wallet which Client Identifier Prefix and Client Identifier to use
     * when authenticating the client through verification of the request signature or retrieving
     * client metadata.
     *
     * See also [clientIdWithoutPrefix] and the notes there.
     */
    @SerialName("client_id")
    val clientId: String

    /**
     * OAuth2: Required
     * OIDC: REQUIRED. OAuth 2.0 Response Type value that determines the authorization processing flow to be used,
     * including what parameters are returned from the endpoints used. When using the Authorization Code Flow, this
     * value is `code`.
     *
     * For OIDC SIOPv2, this is typically `id_token`. For OID4VP, this is typically `vp_token`.
     *
     * Optional when JAR (RFC9101) is used.
     */
    @SerialName("response_type")
    val responseType: String

    /**
     * OAuth2: Optional
     * OIDC: REQUIRED. Redirection URI to which the response will be sent. This URI MUST exactly match one of the
     * Redirection URI values for the Client pre-registered at the OpenID Provider, with the matching performed as
     * described in Section 6.2.1 of RFC3986 (Simple String Comparison).
     *
     * Optional when JAR (RFC9101) is used.
     *
     * See also [redirectUrlExtracted]
     */
    @SerialName("redirect_uri")
    val redirectUrl: String?

    /**
     * OAuth2: Optional
     * OIDC: REQUIRED. OpenID Connect requests MUST contain the openid scope value. If the openid scope value is not
     * present, the behavior is entirely unspecified. Other scope values MAY be present. Scope values used that are not
     * understood by an implementation SHOULD be ignored.
     * e.g. `profile` or `com.example.healthCardCredential`
     */
    @SerialName("scope")
    val scope: String?

    /**
     * OAuth2: Recommended
     * OIDC: RECOMMENDED. Opaque value used to maintain state between the request and the callback. Typically,
     * Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this
     * parameter with a browser cookie.
     */
    @SerialName("state")
    val state: String?

    /**
     * RFC9396: The request parameter `authorization_details` contains, in JSON notation, an array of objects.
     * Each JSON object contains the data to specify the authorization requirements for a certain type of resource.
     * The type of resource or access requirement is determined by the [at.asitplus.openid.AuthorizationDetails.type] field.
     *
     * OID4VCI: This parameter MUST be used to convey th details about the Credentials the Wallet wants to obtain.
     * This specification introduces a new authorization details type `openid_credential`.
     */
    @SerialName("authorization_details")
    val authorizationDetails: List<AuthorizationDetails>?

    //ggf RFC7636
    /**
     * RFC7636: A challenge derived from the code verifier that is sent in the authorization request, to be verified
     * against later.
     */
    @SerialName("code_challenge")
    val codeChallenge: String?

    /**
     * RFC7636: A method that was used to derive code challenge.
     */
    @SerialName("code_challenge_method")
    val codeChallengeMethod: String?

    /**
     * RFC8707: In requests to the authorization server, a client MAY indicate the protected resource (a.k.a.
     * resource server, application, API, etc.) to which it is requesting access. Its value MUST be an absolute URI,
     * as specified by Section 4.3 of (RFC3986).
     */
    @SerialName("resource")
    val resource: String?

    /**
     * OAuth 2.0 Responses: OPTIONAL. Informs the Authorization Server of the mechanism to be used for returning
     * Authorization Response parameters from the Authorization Endpoint. This use of this parameter is NOT RECOMMENDED
     * with a value that specifies the same Response Mode as the default Response Mode for the Response Type used.
     *
     * OIDC SIOPv2: This response mode `post` is used to request the Self-Issued OP to deliver the result of the
     * authentication process to a certain endpoint using the HTTP POST method.
     */
    @SerialName("response_mode")
    val responseMode: OpenIdConstants.ResponseMode?

    /**
     * Reads the [at.asitplus.openid.OpenIdConstants.ClientIdScheme] of this request either directly from [clientIdScheme],
     * or by extracting the prefix from [clientId] (as specified in OpenID4VP draft 22 onwards).
     */
    val clientIdSchemeExtracted: ClientIdScheme?
        get() = clientId.let { ClientIdScheme.decodeFromClientId(it) }

    /**
     * Reads the [clientId] and removes the prefix of the [clientIdSchemeExtracted],
     * as specified in OpenID4VP draft 22 onwards.
     * OpenID4VP states that the *full* [clientId] must be used for presentations and anything else.
     */
    val clientIdWithoutPrefix: String?
        get() = clientId.let { clientId ->
            clientIdSchemeExtracted?.let { clientId.removePrefix("${it.stringRepresentation}:") }
        }

    /**
     * Reads the [redirectUrl], or the [clientIdWithoutPrefix] if [clientIdSchemeExtracted] is
     * [OpenIdConstants.ClientIdScheme.RedirectUri], as specified in OpenID4VP draft 22 onwards.
     */
    val redirectUrlExtracted: String?
        get() = redirectUrl
            ?: (clientIdSchemeExtracted as? OpenIdConstants.ClientIdScheme.RedirectUri)?.let { clientIdWithoutPrefix }

}