package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.AttestationChallengeResponse
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.HttpErrorResponseException
import at.asitplus.wallet.lib.HttpExchange
import at.asitplus.wallet.lib.HttpStep
import at.asitplus.wallet.lib.PreparedHttpRequest
import at.asitplus.wallet.lib.ProtocolRequest
import at.asitplus.wallet.lib.ReceivedHttpResponse
import io.ktor.http.*

/** How an [AuthenticatedExchange] authenticates its request. */
internal sealed interface Authentication {
    /** Client authentication at the authorization server, e.g. for token, PAR and token introspection requests. */
    data class Client(
        val oauthMetadata: OAuth2AuthorizationServerMetadata,
        /** Audience of the client attestation PoP, i.e. the issuer identifier of the authorization server. */
        val authorizationServer: String,
        val issuerMetadata: IssuerMetadata?,
    ) : Authentication

    /** Access to a protected resource with an access token, e.g. for credential and userinfo requests. */
    data class AccessToken(val tokenResponse: TokenResponseParameters) : Authentication
}

/**
 * Sends [request] with the headers for [authentication], retrying at most [maxRetries] times when the server asks for
 * a DPoP nonce or an attestation challenge. Before each attempt with client authentication, an attestation challenge
 * may be fetched first, see [OAuth2ProtocolClient.attestationChallengeRequest].
 *
 * The body of [request] is built only once by the caller, and reused for every attempt; only the headers are rebuilt.
 */
internal class AuthenticatedExchange<T>(
    private val client: OAuth2ProtocolClient,
    private val authentication: Authentication,
    private val maxRetries: Int,
    private val kind: (PreparedHttpRequest, Int) -> ProtocolRequest,
    private val request: PreparedHttpRequest,
    private val parse: suspend (ReceivedHttpResponse) -> T,
) : HttpExchange<T> {

    private sealed interface State {
        data object Start : State
        data class AwaitingChallenge(val attempt: Int) : State
        data class AwaitingResponse(val attempt: Int) : State
        data object Finished : State
    }

    private var state: State = State.Start

    /** Loaded for each attempt before fetching a challenge, so that a request that cannot authenticate is never sent. */
    private var clientAttestation: JwsCompactTyped<JsonWebToken>? = null

    override suspend fun next(response: ReceivedHttpResponse?): KmmResult<HttpStep<T>> = catching {
        val current = state
        state = State.Finished // any failure below ends the exchange
        when (current) {
            State.Start -> {
                check(response == null) { "The first call of next() must not pass a response" }
                startAttempt(0)
            }

            is State.AwaitingChallenge -> sendAttempt(current.attempt, response.required().toAttestationChallenge())
            is State.AwaitingResponse -> handleResponse(current.attempt, response.required())
            State.Finished -> throw IllegalStateException("Exchange is already finished")
        }
    }

    private suspend fun startAttempt(attempt: Int): HttpStep<T> = when (authentication) {
        is Authentication.AccessToken -> sendAttempt(attempt, null)
        is Authentication.Client -> {
            clientAttestation = client.loadClientAttestation(authentication)
            client.attestationChallengeRequest(authentication, request.url, clientAttestation)
                ?.let {
                    state = State.AwaitingChallenge(attempt)
                    HttpStep.Send(ProtocolRequest.AttestationChallenge(it))
                }
                ?: sendAttempt(attempt, null)
        }
    }

    private suspend fun sendAttempt(attempt: Int, fetchedChallenge: String?): HttpStep<T> {
        val authenticationHeaders = when (authentication) {
            is Authentication.AccessToken ->
                client.accessTokenHeaders(authentication.tokenResponse, request.url, request.method)

            is Authentication.Client -> client.clientAuthenticationHeaders(
                authentication = authentication,
                resourceUrl = request.url,
                httpMethod = request.method,
                clientAttestation = clientAttestation,
                fetchedChallenge = fetchedChallenge,
            )
        }
        state = State.AwaitingResponse(attempt)
        return HttpStep.Send(
            kind(
                request.copy(headers = Headers.build {
                    appendAll(request.headers)
                    appendAll(authenticationHeaders)
                }),
                attempt,
            )
        )
    }

    private suspend fun handleResponse(attempt: Int, response: ReceivedHttpResponse): HttpStep<T> {
        when (authentication) {
            is Authentication.Client -> client.recordAuthorizationServerResponse(request.url, response.headers)
            is Authentication.AccessToken -> client.recordResourceServerResponse(request.url, response.headers)
        }
        if (response.status.isSuccess()) {
            return HttpStep.Done(parse(response))
        }
        val error = HttpErrorResponseException(response.status, response.headers, response.body)
        val requested = error.oauth2Error.dpopNonce(error.headers)?.takeIf { it.isNotBlank() }
            ?: error.oauth2Error.attestationChallenge(error.headers)?.takeIf { it.isNotBlank() }
                ?.takeIf { authentication is Authentication.Client }
        if (requested != null && attempt < maxRetries) {
            return startAttempt(attempt + 1)
        }
        throw error
    }

    /** Not cached: the challenge is used for the attempt being built right now, and is single-use. */
    private fun ReceivedHttpResponse.toAttestationChallenge(): String? = takeIf { it.status.isSuccess() }?.let {
        catchingUnwrapped {
            joseCompliantSerializer.decodeFromString<AttestationChallengeResponse>(it.body).attestationChallenge
        }.getOrNull()
    }
}

/**
 * Sends the first of [candidates], and the next one only if the previous one failed, i.e. its response was not
 * successful or could not be [parse]d.
 */
internal class PlainExchange<T>(
    private val candidates: List<ProtocolRequest>,
    private val parse: suspend (ReceivedHttpResponse) -> T,
    private val onResponse: (url: String, response: ReceivedHttpResponse) -> Unit = { _, _ -> },
) : HttpExchange<T> {

    /** Index of the candidate awaiting its response, `-1` before the start. */
    private var current = -1

    override suspend fun next(response: ReceivedHttpResponse?): KmmResult<HttpStep<T>> = catching {
        val index = current
        current = candidates.size // any failure below ends the exchange
        when (index) {
            -1 -> {
                check(response == null) { "The first call of next() must not pass a response" }
                current = 0
                HttpStep.Send(candidates.first())
            }

            in candidates.indices -> {
                val received = response.required()
                onResponse(candidates[index].http.url, received)
                val result = if (received.status.isSuccess()) {
                    catchingUnwrapped { parse(received) }
                } else {
                    Result.failure(HttpErrorResponseException(received.status, received.headers, received.body))
                }
                result.fold(
                    onSuccess = { HttpStep.Done(it) },
                    onFailure = {
                        if (index + 1 >= candidates.size) throw it
                        current = index + 1
                        HttpStep.Send(candidates[index + 1])
                    }
                )
            }

            else -> throw IllegalStateException("Exchange is already finished")
        }
    }
}

/** Creates the actual exchange on the first call of [next], so that errors of [create] fail the exchange. */
internal class LazyExchange<T>(
    private val create: suspend () -> HttpExchange<T>,
) : HttpExchange<T> {

    private var started = false
    private var delegate: HttpExchange<T>? = null

    override suspend fun next(response: ReceivedHttpResponse?): KmmResult<HttpStep<T>> =
        delegate?.next(response) ?: catching {
            check(!started) { "Exchange is already finished" }
            started = true
            check(response == null) { "The first call of next() must not pass a response" }
            create().also { delegate = it }.next().getOrThrow()
        }
}

/** Finishes with [value] on the first call of [next], without sending any request. */
internal class ValueExchange<T>(
    private val value: T,
) : HttpExchange<T> {

    private var finished = false

    override suspend fun next(response: ReceivedHttpResponse?): KmmResult<HttpStep<T>> = catching {
        check(!finished) { "Exchange is already finished" }
        finished = true
        check(response == null) { "The first call of next() must not pass a response" }
        HttpStep.Done(value)
    }
}

private fun ReceivedHttpResponse?.required(): ReceivedHttpResponse =
    checkNotNull(this) { "The response to the last request is missing" }
