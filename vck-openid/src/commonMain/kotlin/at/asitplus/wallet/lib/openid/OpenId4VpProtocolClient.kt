package at.asitplus.wallet.lib.openid

import at.asitplus.catchingUnwrapped
import at.asitplus.openid.encodeToParameters
import at.asitplus.openid.formUrlEncode
import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import at.asitplus.rfc3986uri.Rfc3986UriReference
import at.asitplus.rfc3986uri.Rfc3986UriSchemeName
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.HttpErrorResponseException
import at.asitplus.wallet.lib.HttpExchange
import at.asitplus.wallet.lib.PreparedHttpRequest
import at.asitplus.wallet.lib.ProtocolRequest
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.oauth2.LazyExchange
import at.asitplus.wallet.lib.oauth2.PlainExchange
import at.asitplus.wallet.lib.oauth2.ValueExchange
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Implements the wallet side of
 * [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) 1.0,
 * without sending any HTTP request itself: every call returns an [HttpExchange], whose requests the caller sends with
 * any HTTP stack. The KDoc of each method lists the [ProtocolRequest]s its exchange sends.
 *
 * The caller runs the exchanges of a presentation in order: [prepareAuthorizationResponse] for the request, then,
 * after asking the user for consent, [OpenId4VpHolder.finalizeAuthorizationResponse] of [openId4VpHolder], and
 * [sendAuthorizationResponse] for a response to be posted to the verifier (response modes `direct_post` and
 * `direct_post.jwt`). [openId4VpHolder] validates the requests, matches credentials, and creates the responses.
 *
 * Requests that have already been parsed need no HTTP request to be prepared, so pass them to
 * [OpenId4VpHolder.startAuthorizationResponsePreparation] directly, or, for requests received through the Digital
 * Credentials API, to [DcApiHolder.startAuthorizationResponsePreparation].
 */
class OpenId4VpProtocolClient(
    /** Validates authorization requests, and creates authorization responses. */
    val openId4VpHolder: OpenId4VpHolder,
) {

    /**
     * Parses [input], i.e. a URL, the form-encoded parameters or a request object of an authorization request, and
     * validates it with [OpenId4VpHolder.startAuthorizationResponsePreparation] of [openId4VpHolder]. Show the
     * resulting state to the user, and resume with [OpenId4VpHolder.finalizeAuthorizationResponse].
     *
     * A request object passed by reference in `request_uri` is fetched with GET (RFC 9101), or, for
     * `request_uri_method=post`, with POST and `wallet_metadata` and `wallet_nonce` as form
     * ([OpenID4VP 1.0, 5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request-uri-method-post)),
     * always with `Accept: application/oauth-authz-req+jwt`. The body of a successful answer is the request object,
     * whatever its `Content-Type`; it is decrypted if it has been encrypted to the key advertised in `wallet_metadata`,
     * and must carry the `wallet_nonce` sent. A non-success answer, including a redirect, fails with
     * [HttpErrorResponseException].
     *
     * Sends `[RequestObject]`, i.e. `RequestObject` for a request object passed by reference only.
     */
    fun prepareAuthorizationResponse(
        input: String,
    ): HttpExchange<AuthorizationResponsePreparationState> = LazyExchange {
        when (val parsed = openId4VpHolder.parseWithoutFetching(input)) {
            is RequestParser.ParsedRequest.Resolved -> ValueExchange(
                openId4VpHolder.startAuthorizationResponsePreparation(parsed.request.requireAuthenticationRequest())
                    .getOrThrow()
            )

            is RequestParser.ParsedRequest.ByReference -> PlainExchange(
                candidates = listOf(ProtocolRequest.RequestObject(parsed.toHttpRequest())),
                parse = {
                    openId4VpHolder.startAuthorizationResponsePreparation(
                        openId4VpHolder.resolveFetchedRequestObject(parsed, it.body)
                    ).getOrThrow()
                },
            )
        }
    }

    /**
     * Posts [response], an authorization response or authorization error response for the response modes
     * `direct_post` and `direct_post.jwt`, to the verifier, as `application/x-www-form-urlencoded` without a
     * `charset` parameter, which some strict mDoc verifiers reject.
     *
     * Finishes with the `redirect_uri` from the JSON body of the verifier's successful answer, which the wallet shall
     * open in the user agent, or with `null` if the body is empty, no JSON, or has no `redirect_uri`
     * ([OpenID4VP 1.0, 8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_post)).
     * A `Location` header is ignored. A non-success answer, including a redirect, fails with
     * [HttpErrorResponseException].
     *
     * A `redirect_uri` that is not an absolute `https` URI with a host fails the exchange with an
     * [IllegalArgumentException], although the verifier has already processed [response] at that point. OpenID4VP
     * 1.0, 8.2 only requires an absolute URI, so `https` is a policy of VC-K: the URI carries the fresh secret that
     * protects against session fixation
     * ([OpenID4VP 1.0, 14.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-session-fixation)),
     * and other schemes, e.g. `javascript:`, `data:`, `intent:` or custom app schemes, would let the verifier run
     * scripts or open other apps on the wallet's device. Any host is accepted, but an `https` URI without one is
     * invalid ([RFC 9110, 4.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.2)).
     *
     * Sends `AuthorizationResponse`.
     */
    fun sendAuthorizationResponse(
        response: AuthenticationResponseResult.Post,
    ): HttpExchange<String?> = PlainExchange(
        candidates = listOf(
            ProtocolRequest.AuthorizationResponse(
                PreparedHttpRequest(
                    url = response.url,
                    method = HttpMethod.Post,
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded.toString()),
                    body = response.params.formUrlEncode(),
                )
            )
        ),
        parse = { it.body.toRedirectUri()?.requireHttpsUri() },
    )

    private fun RequestParser.ParsedRequest.ByReference.toHttpRequest(): PreparedHttpRequest {
        val accept = HttpHeaders.Accept to listOf(MediaTypes.Application.AUTHZ_REQ_JWT)
        return if (method == HttpMethod.Post) PreparedHttpRequest(
            url = uri,
            method = HttpMethod.Post,
            headers = headersOf(
                accept,
                HttpHeaders.ContentType to listOf(ContentType.Application.FormUrlEncoded.toString()),
            ),
            body = requestObjectParameters?.encodeToParameters()?.formUrlEncode().orEmpty(),
        ) else PreparedHttpRequest(url = uri, method = method, headers = headersOf(accept))
    }

    private fun String.toRedirectUri(): String? = catchingUnwrapped {
        joseCompliantSerializer.decodeFromString<OpenId4VpSuccess>(this)
    }.getOrNull()?.redirectUri?.ifEmpty { null }

    private fun String.requireHttpsUri(): String {
        val uri = catchingUnwrapped { Rfc3986UriReference(this) }.getOrNull()
        require(
            uri is Rfc3986UniformResourceIdentifier
                    && uri.schemeName == Rfc3986UriSchemeName.Common.HTTPS
                    && uri.authority?.host?.toString()?.isNotEmpty() == true
        ) { "redirect_uri of the verifier is not an absolute https URI: $this" }
        return this
    }
}

/**
 * The verifier's answer to an authorization response posted with the response mode `direct_post` or
 * `direct_post.jwt`, see
 * [OpenID4VP 1.0, 8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_post).
 */
@Serializable
data class OpenId4VpSuccess(
    /** The URI the wallet shall open in the user agent, see [OpenId4VpProtocolClient.sendAuthorizationResponse]. */
    @SerialName("redirect_uri")
    val redirectUri: String,
)
