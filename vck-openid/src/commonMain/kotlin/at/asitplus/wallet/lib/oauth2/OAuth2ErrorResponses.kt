package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OpenIdConstants.Errors.INVALID_DPOP_PROOF
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_TOKEN
import at.asitplus.openid.OpenIdConstants.Errors.USE_DPOP_NONCE
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.wallet.lib.PreparedHttpResponse
import at.asitplus.wallet.lib.jsonHttpResponse
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.ktor.http.*

/**
 * Converts this error of an authorization server endpoint (pushed authorization request, token, token introspection,
 * attestation challenge, authorization) to the response to send: status 400 with the [toOAuth2Error] as JSON
 * ([RFC 6749 5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)), including the header `DPoP-Nonce` for
 * [OAuth2Exception.UseDpopNonce] ([RFC 9449 8.](https://datatracker.ietf.org/doc/html/rfc9449#section-8)) and
 * `OAuth-Client-Attestation-Challenge` for [OAuth2Exception.UseAttestationChallenge]
 * ([OA-ABCA 7.4](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html#errors)).
 *
 * `invalid_client` stays at 400: RFC 6749 5.2 requires 401 only for clients that authenticated with the
 * `Authorization` header, which neither attestation-based client authentication nor public clients use.
 *
 * Use [toResourceServerHttpResponse] for errors of endpoints accessed with an access token.
 */
fun OAuth2Exception.toHttpResponse(): PreparedHttpResponse = toErrorResponse(HttpStatusCode.BadRequest)

/**
 * Converts this error of a resource endpoint accessed with an access token (credential, userinfo) to the response to
 * send, with the [toOAuth2Error] as JSON:
 * - `invalid_token` and `invalid_dpop_proof`: status 401 with `WWW-Authenticate`
 *   ([RFC 6750 3.](https://datatracker.ietf.org/doc/html/rfc6750#section-3),
 *   [RFC 9449 7.1](https://datatracker.ietf.org/doc/html/rfc9449#section-7.1))
 * - `use_dpop_nonce`: status 401 with `WWW-Authenticate` and `DPoP-Nonce`
 *   ([RFC 9449 9.](https://datatracker.ietf.org/doc/html/rfc9449#section-9))
 * - any other error, e.g. the credential errors of OpenID4VCI: status 400, for `use_attestation_challenge` with
 *   `OAuth-Client-Attestation-Challenge`
 *   ([OA-ABCA 7.4](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html#errors))
 *
 * [authorizationHeader] is the value of the request's `Authorization` header, whose scheme (`DPoP` or `Bearer`) is
 * used for `WWW-Authenticate`; `use_dpop_nonce` and `invalid_dpop_proof` always use `DPoP`, and a missing header
 * `Bearer`. `WWW-Authenticate` carries only the error code, never the description.
 */
fun OAuth2Exception.toResourceServerHttpResponse(
    authorizationHeader: String?
): PreparedHttpResponse = when (error) {
    INVALID_TOKEN -> toErrorResponse(HttpStatusCode.Unauthorized) {
        append(HttpHeaders.WWWAuthenticate, wwwAuthenticate(authorizationHeader.scheme()))
    }

    INVALID_DPOP_PROOF, USE_DPOP_NONCE -> toErrorResponse(HttpStatusCode.Unauthorized) {
        append(HttpHeaders.WWWAuthenticate, wwwAuthenticate(TOKEN_TYPE_DPOP))
    }

    else -> toErrorResponse(HttpStatusCode.BadRequest)
}

private fun OAuth2Exception.toErrorResponse(
    status: HttpStatusCode,
    extraHeaders: HeadersBuilder.() -> Unit = {},
) = jsonHttpResponse(toOAuth2Error(), status) {
    (this@toErrorResponse as? OAuth2Exception.UseDpopNonce)?.let { append(HttpHeaders.DPoPNonce, it.dpopNonce) }
    (this@toErrorResponse as? OAuth2Exception.UseAttestationChallenge)?.let {
        append(HttpHeaders.OAuthClientAttestationChallenge, it.attestationChallenge)
    }
    extraHeaders()
}

private fun OAuth2Exception.wwwAuthenticate(scheme: String) = "$scheme error=\"$error\""

/** Auth schemes are case-insensitive, see [RFC 9110 11.1](https://www.rfc-editor.org/rfc/rfc9110#section-11.1). */
private fun String?.scheme(): String =
    if (this?.trim()?.substringBefore(' ').equals(TOKEN_TYPE_DPOP, ignoreCase = true)) TOKEN_TYPE_DPOP
    else SCHEME_BEARER

private const val SCHEME_BEARER = "Bearer"
