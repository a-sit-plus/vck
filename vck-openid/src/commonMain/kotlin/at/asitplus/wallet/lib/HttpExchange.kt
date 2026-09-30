package at.asitplus.wallet.lib

import at.asitplus.KmmResult
import io.ktor.http.*

/**
 * A request to send. [body] is already encoded, e.g. as form, JSON or JWT, and its media type is set as
 * `Content-Type` in [headers].
 */
data class PreparedHttpRequest(
    val url: String,
    val method: HttpMethod,
    val headers: Headers = Headers.Empty,
    val body: String? = null,
)

/** The server's answer, whatever the status code. Callers must not follow redirects. */
data class ReceivedHttpResponse(
    val status: HttpStatusCode,
    val headers: Headers,
    val body: String,
)

/**
 * Every HTTP request the OAuth 2.0 and OpenID4VCI protocol clients hand out, see
 * [at.asitplus.wallet.lib.oauth2.OAuth2ProtocolClient]. Each method returning an [HttpExchange] documents which of
 * these kinds it sends, in which order, and how often. [attempt] starts at 0 for the first attempt of a request, and
 * is increased for each retry.
 */
sealed class ProtocolRequest {
    abstract val http: PreparedHttpRequest

    /**
     * GET the authorization server metadata from `/.well-known/oauth-authorization-server`, or, as a fallback, from
     * `/.well-known/openid-configuration` (then [openidConfiguration] is `true`).
     */
    data class AuthorizationServerMetadata(
        override val http: PreparedHttpRequest,
        val openidConfiguration: Boolean,
    ) : ProtocolRequest()

    /** GET the credential issuer metadata from `/.well-known/openid-credential-issuer`. */
    data class CredentialIssuerMetadata(override val http: PreparedHttpRequest) : ProtocolRequest()

    /** POST to the `challenge_endpoint` of the authorization server, to get an attestation challenge. */
    data class AttestationChallenge(override val http: PreparedHttpRequest) : ProtocolRequest()

    /** POST a pushed authorization request to the `pushed_authorization_request_endpoint`, with client authentication. */
    data class PushedAuthorization(override val http: PreparedHttpRequest, val attempt: Int) : ProtocolRequest()

    /** POST a token request to the `token_endpoint`, with client authentication. */
    data class Token(override val http: PreparedHttpRequest, val attempt: Int) : ProtocolRequest()

    /** POST a token introspection request to the `introspection_endpoint`, with client authentication. */
    data class TokenIntrospection(override val http: PreparedHttpRequest, val attempt: Int) : ProtocolRequest()

    /** POST to the `nonce_endpoint` of the credential issuer. */
    data class Nonce(override val http: PreparedHttpRequest) : ProtocolRequest()

    /** POST a credential request to the `credential_endpoint`, with the access token. */
    data class Credential(override val http: PreparedHttpRequest, val attempt: Int) : ProtocolRequest()

    /** GET the `userinfo_endpoint`, with the access token. */
    data class UserInfo(override val http: PreparedHttpRequest, val attempt: Int) : ProtocolRequest()
}

/** One step of an [HttpExchange]. */
sealed interface HttpStep<out T> {
    /** Send [request] and pass the response to the next call of [HttpExchange.next]. */
    data class Send(val request: ProtocolRequest) : HttpStep<Nothing>

    /** The exchange is finished with [value]. */
    data class Done<T>(val value: T) : HttpStep<T>
}

/**
 * One logical call of a protocol, which may need more than one HTTP request, e.g. to fetch an attestation challenge
 * or to retry with a nonce the server asked for. The method returning the exchange documents which
 * [ProtocolRequest]s it sends.
 *
 * Call [next] without a response first, then send every [HttpStep.Send.request] and pass its response to [next],
 * until the exchange returns [HttpStep.Done]:
 *
 * ```
 * var step = exchange.next().getOrThrow()
 * while (step is HttpStep.Send) step = exchange.next(send(step.request.http)).getOrThrow()
 * return (step as HttpStep.Done).value
 * ```
 *
 * An exchange can be used only once, and is not thread-safe. It fails with [HttpErrorResponseException] for a
 * non-success response once no retry applies, and cannot be used after any failure.
 */
interface HttpExchange<T> {
    suspend fun next(response: ReceivedHttpResponse? = null): KmmResult<HttpStep<T>>
}
