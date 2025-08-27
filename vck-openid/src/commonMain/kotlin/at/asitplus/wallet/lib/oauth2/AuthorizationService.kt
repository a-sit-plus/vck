package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2LoadUserFun
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import kotlinx.serialization.json.JsonObject

/**
 * Provides interface for implementing an OAuth 2.0 Authorization Server, which may be used with an
 * [at.asitplus.wallet.lib.oidvci.OAuth2AuthorizationServerAdapter] for a
 * [at.asitplus.wallet.lib.oidvci.CredentialIssuer].
 */
interface AuthorizationService {

    @Deprecated(
        "Use par with RequestInfo instead",
        ReplaceWith("par(input, RequestInfo(clientAttestation = clientAttestation, clientAttestationPop = clientAttestationPop))")
    )
    suspend fun par(
        input: String,
        clientAttestation: String? = null,
        clientAttestationPop: String? = null,
    ): KmmResult<PushedAuthenticationResponseParameters>

    @Deprecated(
        "Use par with RequestInfo instead",
        ReplaceWith("par(request, RequestInfo(clientAttestation = clientAttestation, clientAttestationPop = clientAttestationPop))")
    )
    suspend fun par(
        request: AuthenticationRequestParameters,
        clientAttestation: String? = null,
        clientAttestationPop: String? = null,
    ): KmmResult<PushedAuthenticationResponseParameters>

    /**
     * Pushed authorization request endpoint as defined in [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html).
     * Clients send their authorization request as HTTP `POST` with `application/x-www-form-urlencoded` to the AS.
     *
     * Responses have to be sent with HTTP status code `201`.
     *
     * @param input as sent from the client as `POST` body
     * @param httpRequest information about the HTTP request from the client to validate authentication
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun par(
        input: String,
        httpRequest: RequestInfo? = null,
    ): KmmResult<PushedAuthenticationResponseParameters>

    /**
     * Pushed authorization request endpoint as defined in [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html).
     * Clients send their authorization request as HTTP `POST` with `application/x-www-form-urlencoded` to the AS.
     *
     * Responses have to be sent with HTTP status code `201`.
     *
     * @param request as sent from the client as `POST`
     * @param httpRequest information about the HTTP request from the client to validate authentication
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun par(
        request: AuthenticationRequestParameters,
        httpRequest: RequestInfo? = null,
    ): KmmResult<PushedAuthenticationResponseParameters>

    /**
     * Builds the authentication response for this specific user from [loadUserFun]
     * (called when request has been validated).
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return URL built from client's `redirect_uri` with `code` parameter, [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun authorize(
        input: AuthenticationRequestParameters,
        loadUserFun: OAuth2LoadUserFun,
    ): KmmResult<AuthenticationResponseResult.Redirect>

    /**
     * Verifies the authorization code sent by the client and issues an access token.
     * Send this value JSON-serialized back to the client.

     * @param request as sent from the client as `POST`
     * @param httpRequest information about the HTTP request from the client, to validate authentication
     *
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun token(
        request: TokenRequestParameters,
        httpRequest: RequestInfo? = null,
    ): KmmResult<TokenResponseParameters>

    /**
     * Returns the user info associated with this access token, when the token in [authorizationHeader] is correct.
     */
    suspend fun userInfo(
        authorizationHeader: String,
        httpRequest: RequestInfo? = null,
    ): KmmResult<JsonObject>

    /**
     * [RFC7662](https://datatracker.ietf.org/doc/html/rfc7662): OAuth 2.0 Token Introspection
     *
     * @param request as sent from the client as form POST
     * @param httpRequest information about the HTTP request from the client, to validate authentication
     */
    suspend fun tokenIntrospection(
        request: TokenIntrospectionRequest,
        httpRequest: RequestInfo? = null,
    ): KmmResult<TokenIntrospectionResponse>
}