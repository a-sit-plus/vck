package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2LoadUserFun
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult

interface AuthorizationService {

    /**
     * Pushed authorization request endpoint as defined in [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html).
     * Clients send their authorization request as HTTP `POST` with `application/x-www-form-urlencoded` to the AS.
     *
     * Responses have to be sent with HTTP status code `201`.
     *
     * @param input as sent from the client as `POST`
     * @param clientAttestation value of the header `OAuth-Client-Attestation`
     * @param clientAttestationPop value of the header `OAuth-Client-Attestation-PoP`
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun par(
        input: String,
        clientAttestation: String? = null,
        clientAttestationPop: String? = null,
    ): KmmResult<PushedAuthenticationResponseParameters>


    /**
     * Pushed authorization request endpoint as defined in [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html).
     * Clients send their authorization request as HTTP `POST` with `application/x-www-form-urlencoded` to the AS.
     *
     * Responses have to be sent with HTTP status code `201`.
     *
     * @param request as sent from the client as `POST`
     * @param clientAttestation value of the header `OAuth-Client-Attestation`
     * @param clientAttestationPop value of the header `OAuth-Client-Attestation-PoP`
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun par(
        request: JarRequestParameters,
        clientAttestation: String? = null,
        clientAttestationPop: String? = null,
    ): KmmResult<PushedAuthenticationResponseParameters>

    /**
     * Pushed authorization request endpoint as defined in [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html).
     * Clients send their authorization request as HTTP `POST` with `application/x-www-form-urlencoded` to the AS.
     *
     * Responses have to be sent with HTTP status code `201`.
     *
     * @param request as sent from the client as `POST`
     * @param clientAttestation value of the header `OAuth-Client-Attestation`
     * @param clientAttestationPop value of the header `OAuth-Client-Attestation-PoP`
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun par(
        request: AuthenticationRequestParameters,
        clientAttestation: String? = null,
        clientAttestationPop: String? = null,
    ): KmmResult<PushedAuthenticationResponseParameters>

    /**
     * Builds the authentication response for this specific user from [loadUserFun].
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun authorize(
        input: JarRequestParameters,
        loadUserFun: OAuth2LoadUserFun,
    ): KmmResult<AuthenticationResponseResult.Redirect>

    /**
     * Builds the authentication response for this specific user from [loadUserFun].
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return [KmmResult] may contain a [OAuth2Exception]
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
}