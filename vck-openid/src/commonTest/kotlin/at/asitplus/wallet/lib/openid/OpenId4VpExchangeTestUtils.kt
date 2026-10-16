package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.decodeFromFormUrlEncoded
import at.asitplus.wallet.lib.ReceivedHttpResponse
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.oauth2.FakeHttpStack
import at.asitplus.wallet.lib.oauth2.scripted
import io.ktor.http.*

/**
 * Prepares the authorization request [input] as a wallet does, i.e. with
 * [OpenId4VpProtocolClient.prepareAuthorizationResponse], sending its requests with [http]. By default, no request
 * is expected, as for requests passed by value.
 */
suspend fun OpenId4VpHolder.prepareAuthorizationResponse(
    input: String,
    http: FakeHttpStack = FakeHttpStack(scripted()),
): KmmResult<AuthorizationResponsePreparationState> = catching {
    http.execute(OpenId4VpProtocolClient(this).prepareAuthorizationResponse(input))
}

/**
 * Prepares [input] as [prepareAuthorizationResponse] does, and creates the response with the presentation the request
 * asks for, without user interaction.
 */
suspend fun OpenId4VpHolder.createAuthorizationResponse(
    input: String,
    http: FakeHttpStack = FakeHttpStack(scripted()),
): KmmResult<AuthenticationResponseResult> = catching {
    finalizeAuthorizationResponse(prepareAuthorizationResponse(input, http).getOrThrow()).getOrThrow()
}

/**
 * Plays the verifier's `request_uri` endpoint at [requestUrl]: answers with the request object [serve] returns for the
 * `wallet_metadata` and `wallet_nonce` the wallet has posted (`null` for GET), and every other request with 404.
 */
fun requestUriEndpoint(
    requestUrl: String,
    serve: suspend (RequestObjectParameters?) -> String,
) = FakeHttpStack { request ->
    if (request.url == requestUrl) ReceivedHttpResponse(
        status = HttpStatusCode.OK,
        headers = headersOf(HttpHeaders.ContentType, MediaTypes.Application.AUTHZ_REQ_JWT),
        body = serve(request.body?.decodeFromFormUrlEncoded<RequestObjectParameters>()),
    ) else ReceivedHttpResponse(HttpStatusCode.NotFound, Headers.Empty, "")
}
