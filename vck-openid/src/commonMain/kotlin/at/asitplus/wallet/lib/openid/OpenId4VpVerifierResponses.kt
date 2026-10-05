package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.wallet.lib.PreparedHttpResponse
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.jsonHttpResponse
import at.asitplus.wallet.lib.oauth2.NO_STORE
import io.ktor.http.*
import kotlinx.serialization.json.JsonObject

/**
 * Loads the request object with [CreatedRequest.loadRequestObject], passing the [params] the wallet may have sent
 * (`wallet_metadata` and `wallet_nonce` for `request_uri_method=post`), and converts it to the response of the request
 * URI: status 200 with the signed, optionally encrypted, request object as `application/oauth-authz-req+jwt`
 * ([OpenID4VP 1.0 5.10.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10.1),
 * [RFC 9101 5.2.3](https://www.rfc-editor.org/rfc/rfc9101#section-5.2.3)).
 *
 * Fails for requests without a request object to serve, i.e. not created by reference.
 */
suspend fun CreatedRequest.loadRequestObjectHttpResponse(
    params: RequestObjectParameters?,
): KmmResult<PreparedHttpResponse> = catching {
    val load = checkNotNull(loadRequestObject) { "No request object to serve for $url" }
    PreparedHttpResponse(
        status = HttpStatusCode.OK,
        headers = headersOf(HttpHeaders.ContentType, MediaTypes.Application.AUTHZ_REQ_JWT),
        body = load(params).getOrThrow(),
    )
}

/**
 * The answer of the response endpoint, after it has processed an authorization response or authorization error
 * response posted with the response mode `direct_post` or `direct_post.jwt`: status 200 with a JSON object, holding
 * [redirectUri] as `redirect_uri` if present
 * ([OpenID4VP 1.0 8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2)), see
 * [OpenId4VpSuccess]. The header `Cache-Control: no-store` keeps the `redirect_uri` out of caches, as it should carry
 * a fresh secret against session fixation
 * ([OpenID4VP 1.0 14.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-14.2)), as in the
 * example of 8.2.
 */
fun directPostHttpResponse(redirectUri: String? = null): PreparedHttpResponse =
    if (redirectUri != null) jsonHttpResponse(OpenId4VpSuccess(redirectUri)) { noStore() }
    else jsonHttpResponse(JsonObject(emptyMap())) { noStore() }

private fun HeadersBuilder.noStore() = append(HttpHeaders.CacheControl, NO_STORE)
