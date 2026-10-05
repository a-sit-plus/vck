package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AttestationChallengeResponse
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.TokenIntrospectionJwtResponse
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenIntrospectionResult
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.wallet.lib.PreparedHttpResponse
import at.asitplus.wallet.lib.jsonHttpResponse
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import io.ktor.http.*
import kotlinx.serialization.json.JsonObject
import kotlin.jvm.JvmName

/**
 * Converts the authorization server metadata to the response of `/.well-known/oauth-authorization-server` (and
 * `/.well-known/openid-configuration`): status 200 with the metadata as JSON
 * ([RFC 8414 3.2](https://datatracker.ietf.org/doc/html/rfc8414#section-3.2)).
 */
fun OAuth2AuthorizationServerMetadata.toHttpResponse(): PreparedHttpResponse = jsonHttpResponse(this)

/**
 * Converts the challenge to the response of the challenge endpoint: status 200 with the challenge as JSON, and
 * `Cache-Control: no-store`
 * ([OA-ABCA 6.1](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html#challenge-endpoint)).
 */
fun AttestationChallengeResponse.toHttpResponse(): PreparedHttpResponse = jsonHttpResponse(this) {
    append(HttpHeaders.CacheControl, NO_STORE)
}

/**
 * Converts the result of the pushed authorization request endpoint to its response: status 201 with the
 * parameters as JSON ([RFC 9126 2.2](https://datatracker.ietf.org/doc/html/rfc9126#section-2.2)), and the headers
 * `DPoP-Nonce` and `OAuth-Client-Attestation-Challenge`, if present.
 */
@JvmName("pushedAuthorizationToHttpResponse")
fun ResponseWithDpopNonce<PushedAuthenticationResponseParameters>.toHttpResponse(): PreparedHttpResponse =
    jsonHttpResponse(response, HttpStatusCode.Created) { appendFreshValues(this@toHttpResponse) }

/**
 * Converts the result of the authorization endpoint to its response: a redirect with status 302 to the client's
 * redirect URI in `Location` ([RFC 6749 4.1.2](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2)).
 */
fun AuthenticationResponseResult.Redirect.toHttpResponse(): PreparedHttpResponse = PreparedHttpResponse(
    status = HttpStatusCode.Found,
    headers = headersOf(HttpHeaders.Location, url),
)

/**
 * Converts the result of the token endpoint to its response: status 200 with the token response as JSON, the headers
 * `Cache-Control: no-store` and `Pragma: no-cache`
 * ([RFC 6749 5.1](https://datatracker.ietf.org/doc/html/rfc6749#section-5.1)), and the headers `DPoP-Nonce` and
 * `OAuth-Client-Attestation-Challenge`, if present.
 */
@JvmName("tokenToHttpResponse")
fun ResponseWithDpopNonce<TokenResponseParameters>.toHttpResponse(): PreparedHttpResponse =
    jsonHttpResponse(response) {
        append(HttpHeaders.CacheControl, NO_STORE)
        append(HttpHeaders.Pragma, NO_CACHE)
        appendFreshValues(this@toHttpResponse)
    }

/**
 * Converts the result of the token introspection endpoint to its response: status 200 with the result as JSON
 * ([RFC 7662 2.2](https://datatracker.ietf.org/doc/html/rfc7662#section-2.2)), i.e. a
 * [TokenIntrospectionJwtResponse] as `{"jwt": …}`, as [OAuth2ProtocolClient] expects it.
 */
fun TokenIntrospectionResult.toHttpResponse(): PreparedHttpResponse = when (this) {
    is TokenIntrospectionResponse -> jsonHttpResponse(this)
    is TokenIntrospectionJwtResponse -> jsonHttpResponse(this)
}

/**
 * Converts the result of the userinfo endpoint to its response: status 200 with the user info as JSON
 * ([OpenID Connect Core 5.3.2](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse)), and the
 * header `DPoP-Nonce`, if present.
 */
@JvmName("userInfoToHttpResponse")
fun ResponseWithDpopNonce<JsonObject>.toHttpResponse(): PreparedHttpResponse =
    jsonHttpResponse(response) { appendFreshValues(this@toHttpResponse) }

/**
 * [RFC 9449 8.2](https://datatracker.ietf.org/doc/html/rfc9449#section-8.2),
 * [OA-ABCA 6.2](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html#challenge-in-response)
 */
private fun HeadersBuilder.appendFreshValues(result: ResponseWithDpopNonce<*>) {
    result.dpopNonce?.let { append(HttpHeaders.DPoPNonce, it) }
    result.attestationChallenge?.let { append(HttpHeaders.OAuthClientAttestationChallenge, it) }
}

private const val NO_STORE = "no-store"
private const val NO_CACHE = "no-cache"
