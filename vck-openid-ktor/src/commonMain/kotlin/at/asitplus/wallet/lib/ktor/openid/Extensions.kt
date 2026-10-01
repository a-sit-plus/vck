package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catchingUnwrapped
import at.asitplus.openid.OpenIdConstants.Errors.USE_ATTESTATION_CHALLENGE
import at.asitplus.openid.OpenIdConstants.Errors.USE_DPOP_NONCE
import at.asitplus.wallet.lib.oauth2.DPoPNonce
import at.asitplus.wallet.lib.oauth2.OAuthClientAttestationChallenge
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async

fun <T> CoroutineScope.lazyDeferred(
    block: suspend CoroutineScope.() -> T,
): Lazy<Deferred<T>> = lazy {
    async(start = CoroutineStart.LAZY) { block() }
}

/** Extracts the header `DPoP-Nonce` if the error is `use_dpop_nonce`. */
fun OAuth2Error?.dpopNonce(response: HttpResponse) = catchingUnwrapped {
    authorizationServerProvidedNonce(response) ?: resourceServerProvidedNonce(response)
}.getOrNull()

/** Extracts the header `DPoP-Nonce` if the error is `use_dpop_nonce`. */
fun HttpErrorResponseException.dpopNonce() = oauth2Error.dpopNonce(response)

/** Extracts the header `OAuth-Client-Attestation-Challenge` if the error is `use_attestation_challenge`. */
fun OAuth2Error?.attestationChallenge(response: HttpResponse) = catchingUnwrapped {
    authorizationServerProvidedAttestationChallenge(response)
}.getOrNull()

/** Extracts the header `DPoP-Nonce` if the error is `use_dpop_nonce`. */
fun HttpErrorResponseException.attestationChallenge() = oauth2Error.attestationChallenge(response)


/** [RFC 9449 8.](https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid) */
private fun OAuth2Error?.authorizationServerProvidedNonce(response: HttpResponse): String? =
    this?.error.takeIf { it == USE_DPOP_NONCE }?.let { response.headers[HttpHeaders.DPoPNonce] }

/** [RFC 9449 9.](https://datatracker.ietf.org/doc/html/rfc9449#section-9) */
private fun resourceServerProvidedNonce(response: HttpResponse): String? =
    response.takeIf {
        response.headers.getAll(HttpHeaders.WWWAuthenticate)?.any { it.contains(USE_DPOP_NONCE) } == true
    }?.let { response.headers[HttpHeaders.DPoPNonce] }

/** [OA-ABCA 6.2](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html#challenge-in-response) */
private fun OAuth2Error?.authorizationServerProvidedAttestationChallenge(response: HttpResponse): String? =
    this?.error.takeIf { it == USE_ATTESTATION_CHALLENGE }
        ?.let { response.headers[HttpHeaders.OAuthClientAttestationChallenge] }

fun HttpRequestData.toRequestInfo(): RequestInfo = RequestInfo(
    url = url.toString(),
    method = method,
    headers = headers,
)
