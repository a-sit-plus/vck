package at.asitplus.wallet.lib

import at.asitplus.KmmResult
import io.ktor.http.*

/**
 * A request to send. Send every header in [headers], and [body] with its [HttpBody.contentType] as `Content-Type`;
 * [headers] never contain `Content-Type`.
 */
data class PreparedHttpRequest(
    val url: String,
    val method: HttpMethod,
    val headers: Headers = Headers.Empty,
    val body: HttpBody? = null,
) {
    init {
        headers.requireNoContentType()
    }
}

/** The server's answer, whatever the status code. Callers must not follow redirects. */
data class ReceivedHttpResponse(
    val status: HttpStatusCode,
    val headers: Headers,
    val body: String,
)

/**
 * Every HTTP request the OAuth 2.0, OpenID4VCI and OpenID4VP protocol clients hand out, see
 * [at.asitplus.wallet.lib.oauth2.OAuth2ProtocolClient] and [at.asitplus.wallet.lib.openid.OpenId4VpProtocolClient].
 * Each method returning an [HttpExchange] documents which of these kinds it sends, in which order, and how often.
 * Requests that are retried are [Retryable].
 */
sealed class ProtocolRequest {
    abstract val http: PreparedHttpRequest

    /**
     * A request with client authentication or an access token, sent again with fresh authentication headers when the
     * server asks for a DPoP nonce (RFC 9449, 8 and 9) or an attestation challenge
     * (draft-ietf-oauth-attestation-based-client-auth-10, 6.2). [attempt] starts at 0 for the first attempt of a
     * request, and is increased for each retry of the same request. A fallback to another request, e.g.
     * [AuthorizationServerMetadata] with [AuthorizationServerMetadata.openidConfiguration], is not a retry.
     */
    sealed class Retryable : ProtocolRequest() {
        abstract val attempt: Int
    }

    /**
     * GET the authorization server metadata from `/.well-known/oauth-authorization-server`, or, as a fallback, from
     * `/.well-known/openid-configuration` (then [openidConfiguration] is `true`).
     */
    data class AuthorizationServerMetadata(
        override val http: PreparedHttpRequest,
        val openidConfiguration: Boolean,
    ) : ProtocolRequest()

    /** GET the credential offer from the `credential_offer_uri` of a credential offer passed by reference. */
    data class CredentialOffer(override val http: PreparedHttpRequest) : ProtocolRequest()

    /** GET the credential issuer metadata from `/.well-known/openid-credential-issuer`. */
    data class CredentialIssuerMetadata(override val http: PreparedHttpRequest) : ProtocolRequest()

    /** POST to the `challenge_endpoint` of the authorization server, to get an attestation challenge. */
    data class AttestationChallenge(override val http: PreparedHttpRequest) : ProtocolRequest()

    /** POST a pushed authorization request to the `pushed_authorization_request_endpoint`, with client authentication. */
    data class PushedAuthorization(override val http: PreparedHttpRequest, override val attempt: Int) : Retryable()

    /** POST a token request to the `token_endpoint`, with client authentication. */
    data class Token(override val http: PreparedHttpRequest, override val attempt: Int) : Retryable()

    /** POST a token introspection request to the `introspection_endpoint`, with client authentication. */
    data class TokenIntrospection(override val http: PreparedHttpRequest, override val attempt: Int) : Retryable()

    /** POST to the `nonce_endpoint` of the credential issuer. */
    data class Nonce(override val http: PreparedHttpRequest) : ProtocolRequest()

    /** POST a credential request to the `credential_endpoint`, with the access token. */
    data class Credential(override val http: PreparedHttpRequest, override val attempt: Int) : Retryable()

    /** GET the `userinfo_endpoint`, with the access token. */
    data class UserInfo(override val http: PreparedHttpRequest, override val attempt: Int) : Retryable()

    /**
     * GET the request object from the `request_uri` of an OpenID4VP authorization request, or POST `wallet_metadata`
     * and `wallet_nonce` to it as form, for `request_uri_method=post`.
     */
    data class RequestObject(override val http: PreparedHttpRequest) : ProtocolRequest()

    /**
     * POST an OpenID4VP authorization response, or authorization error response, as form to the `response_uri` of
     * the verifier, for the response modes `direct_post` and `direct_post.jwt`.
     */
    data class AuthorizationResponse(override val http: PreparedHttpRequest) : ProtocolRequest()
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
