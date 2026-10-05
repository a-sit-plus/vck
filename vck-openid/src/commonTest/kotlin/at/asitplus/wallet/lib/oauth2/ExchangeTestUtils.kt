package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.FormParameters
import at.asitplus.openid.toFormParameters
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.HttpExchange
import at.asitplus.wallet.lib.HttpStep
import at.asitplus.wallet.lib.PreparedHttpRequest
import at.asitplus.wallet.lib.PreparedHttpResponse
import at.asitplus.wallet.lib.ProtocolRequest
import at.asitplus.wallet.lib.ReceivedHttpResponse
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.openid.toOAuth2Error
import io.ktor.http.*

/**
 * Plays the part of an HTTP stack in tests, like ktor's `MockEngine`: routes every request of an exchange to
 * [handle], and records the [ProtocolRequest]s that have been sent in [sent].
 */
class FakeHttpStack(
    val handle: suspend (PreparedHttpRequest) -> ReceivedHttpResponse,
) {
    val sent = mutableListOf<ProtocolRequest>()

    suspend fun <T> execute(exchange: HttpExchange<T>): T {
        var step = exchange.next().getOrThrow()
        while (step is HttpStep.Send) {
            sent += step.request
            step = exchange.next(handle(step.request.http)).getOrThrow()
        }
        return (step as HttpStep.Done).value
    }

    /** Sends the requests of [exchange] until it would send one of kind [R], which is returned without sending it. */
    suspend inline fun <reified R : ProtocolRequest> firstRequest(exchange: HttpExchange<*>): R {
        var step = exchange.next().getOrThrow()
        while (step is HttpStep.Send) {
            (step.request as? R)?.let { return it }
            sent += step.request
            step = exchange.next(handle(step.request.http)).getOrThrow()
        }
        throw AssertionError("Exchange finished without sending ${R::class.simpleName}")
    }
}

/** Answers with [responses] in order, one per request. */
fun scripted(vararg responses: ReceivedHttpResponse): suspend (PreparedHttpRequest) -> ReceivedHttpResponse {
    val queue = ArrayDeque(responses.toList())
    return { queue.removeFirst() }
}

/** Short labels for sequence assertions, e.g. `Token(1)` for the first retry of a token request. */
fun List<ProtocolRequest>.kinds(): List<String> = map {
    when (it) {
        is ProtocolRequest.AuthorizationServerMetadata ->
            if (it.openidConfiguration) "AuthorizationServerMetadata(openidConfiguration)"
            else "AuthorizationServerMetadata"

        is ProtocolRequest.CredentialOffer -> "CredentialOffer"
        is ProtocolRequest.CredentialIssuerMetadata -> "CredentialIssuerMetadata"
        is ProtocolRequest.AttestationChallenge -> "AttestationChallenge"
        is ProtocolRequest.PushedAuthorization -> "PushedAuthorization(${it.attempt})"
        is ProtocolRequest.Token -> "Token(${it.attempt})"
        is ProtocolRequest.TokenIntrospection -> "TokenIntrospection(${it.attempt})"
        is ProtocolRequest.Nonce -> "Nonce"
        is ProtocolRequest.Credential -> "Credential(${it.attempt})"
        is ProtocolRequest.UserInfo -> "UserInfo(${it.attempt})"
        is ProtocolRequest.RequestObject -> "RequestObject"
        is ProtocolRequest.AuthorizationResponse -> "AuthorizationResponse"
    }
}

fun PreparedHttpRequest.toRequestInfo() = RequestInfo(url = url, method = method, headers = headers)

fun ProtocolRequest.toRequestInfo() = http.toRequestInfo()

val PreparedHttpRequest.path: String
    get() = Url(url).encodedPath

fun PreparedHttpRequest.formParameters(): FormParameters = body.orEmpty().toFormParameters()

/** What the client receives, when a server sends this response. */
fun PreparedHttpResponse.received() = ReceivedHttpResponse(status = status, headers = headers, body = body)

/** Adds the header [name] with [value], e.g. a fresh DPoP nonce alongside an error (RFC 9449 8.2). */
fun ReceivedHttpResponse.withHeader(name: String, value: String) =
    copy(headers = Headers.build { appendAll(headers); append(name, value) })

/**
 * Error response of an authorization server endpoint, see [OAuth2Exception.toHttpResponse], or 500 for anything else.
 */
fun Throwable.toAuthorizationServerResponse(): ReceivedHttpResponse =
    (this as? OAuth2Exception)?.toHttpResponse()?.received()
        ?: ReceivedHttpResponse(HttpStatusCode.InternalServerError, Headers.Empty, "")

inline fun <reified T> jsonResponse(
    value: T,
    extraHeaders: HeadersBuilder.() -> Unit = {},
): ReceivedHttpResponse = ReceivedHttpResponse(
    status = HttpStatusCode.OK,
    headers = Headers.build {
        append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        extraHeaders()
    },
    body = joseCompliantSerializer.encodeToString(value),
)

/**
 * Error response of an authorization server, with the headers asked for by [OAuth2Exception.UseDpopNonce] and
 * [OAuth2Exception.UseAttestationChallenge].
 *
 * @param dpopNonce supply a fresh DPoP nonce alongside an unrelated error, i.e. for an AS that mandates a nonce
 * (RFC 9449 8.) on an endpoint that may reject the request for another reason first
 */
fun Throwable.toErrorResponse(dpopNonce: String? = null): ReceivedHttpResponse = ReceivedHttpResponse(
    status = HttpStatusCode.BadRequest,
    headers = Headers.build {
        append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        ((this@toErrorResponse as? OAuth2Exception.UseDpopNonce)?.dpopNonce ?: dpopNonce)
            ?.let { append(HttpHeaders.DPoPNonce, it) }
        (this@toErrorResponse as? OAuth2Exception.UseAttestationChallenge)?.attestationChallenge
            ?.let { append(HttpHeaders.OAuthClientAttestationChallenge, it) }
    },
    body = joseCompliantSerializer.encodeToString(toOAuth2Error(null)),
)
