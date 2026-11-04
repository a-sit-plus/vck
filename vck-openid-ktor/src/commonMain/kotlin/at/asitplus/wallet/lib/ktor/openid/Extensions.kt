package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.attestationChallenge
import at.asitplus.wallet.lib.oauth2.dpopNonce
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import io.ktor.client.request.*
import io.ktor.client.statement.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async

fun <T> CoroutineScope.lazyDeferred(
    block: suspend CoroutineScope.() -> T,
): Lazy<Deferred<T>> = lazy {
    async(start = CoroutineStart.LAZY) { block() }
}

/** Extracts the header `DPoP-Nonce` if the server asked for it with `use_dpop_nonce`. */
fun OAuth2Error?.dpopNonce(response: HttpResponse) = dpopNonce(response.headers)

/** Extracts the header `OAuth-Client-Attestation-Challenge` if the error is `use_attestation_challenge`. */
fun OAuth2Error?.attestationChallenge(response: HttpResponse) = attestationChallenge(response.headers)

fun HttpRequestData.toRequestInfo(): RequestInfo = RequestInfo(
    url = url.toString(),
    method = method,
    headers = headers,
)
