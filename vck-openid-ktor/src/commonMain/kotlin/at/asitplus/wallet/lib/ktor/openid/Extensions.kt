package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.attestationChallenge
import at.asitplus.wallet.lib.oauth2.dpopNonce
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

/** Extracts the header `DPoP-Nonce` if the server asked for it with `use_dpop_nonce`. */
fun OAuth2Error?.dpopNonce(response: HttpResponse) = dpopNonce(response.headers)

/** Extracts the header `DPoP-Nonce` if the server asked for it with `use_dpop_nonce`. */
@Deprecated(
    "Use the header-based function from vck-openid, which does not depend on a ktor client",
    ReplaceWith("oauth2Error.dpopNonce(headers)", "at.asitplus.wallet.lib.oauth2.dpopNonce"),
)
@Suppress("DEPRECATION")
fun HttpErrorResponseException.dpopNonce() = oauth2Error.dpopNonce(headers)

/** Extracts the header `OAuth-Client-Attestation-Challenge` if the error is `use_attestation_challenge`. */
fun OAuth2Error?.attestationChallenge(response: HttpResponse) = attestationChallenge(response.headers)

/** Extracts the header `OAuth-Client-Attestation-Challenge` if the error is `use_attestation_challenge`. */
@Deprecated(
    "Use the header-based function from vck-openid, which does not depend on a ktor client",
    ReplaceWith("oauth2Error.attestationChallenge(headers)", "at.asitplus.wallet.lib.oauth2.attestationChallenge"),
)
@Suppress("DEPRECATION")
fun HttpErrorResponseException.attestationChallenge() = oauth2Error.attestationChallenge(headers)

fun HttpRequestData.toRequestInfo(): RequestInfo = RequestInfo(
    url = url.toString(),
    method = method,
    headers = headers,
)
