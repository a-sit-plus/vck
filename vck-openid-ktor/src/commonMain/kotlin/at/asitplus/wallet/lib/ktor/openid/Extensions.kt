package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.openid.OpenIdConstants.Errors.USE_DPOP_NONCE
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import io.ktor.client.call.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

fun <T> CoroutineScope.lazyDeferred(
    block: suspend CoroutineScope.() -> T,
): Lazy<Deferred<T>> = lazy {
    async(start = CoroutineStart.LAZY) { block() }
}

/** Intermediate class to perform error handling on ktor responses, see [onFailure] and [onSuccess]. */
sealed class IntermediateResult<R> {
    class Success<R>(val httpResponse: HttpResponse) : IntermediateResult<R>()
    class Failure<R>(val result: R) : IntermediateResult<R>()
}

/** Helper method to perform error handling on ktor responses, see [onSuccess]. */
@OptIn(ExperimentalContracts::class)
suspend inline fun <reified R> HttpResponse.onFailure(
    block: OAuth2Error?.(response: HttpResponse) -> R,
): IntermediateResult<R> {
    contract {
        callsInPlace(block, InvocationKind.AT_MOST_ONCE)
    }
    return if (!status.isSuccess()) {
        val body = catching { this.body<OAuth2Error>() }.getOrNull()
        IntermediateResult.Failure(block(body, this))
    } else {
        IntermediateResult.Success(this)
    }
}

/** Helper method to perform error handling on ktor responses, see [onFailure]. */
@OptIn(ExperimentalContracts::class)
suspend inline fun <reified T, R> IntermediateResult<R>.onSuccess(
    block: T.(response: HttpResponse) -> R,
): R {
    contract {
        callsInPlace(block, InvocationKind.AT_MOST_ONCE)
    }
    return when (this) {
        is IntermediateResult.Failure<R> -> result
        is IntermediateResult.Success<R> -> block(httpResponse.body<T>(), httpResponse)
    }
}

/** Extracts the header `DPoP-Nonce` if the error is `use_dpop_nonce`. */
fun OAuth2Error?.dpopNonce(response: HttpResponse) = runCatching {
    authorizationServerProvidedNonce(response)
        ?: resourceServerProvidedNonce(response)
}.getOrNull()

/** [RFC 9449 8.](https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid) */
private fun OAuth2Error?.authorizationServerProvidedNonce(response: HttpResponse): String? =
    this?.error.takeIf { it == USE_DPOP_NONCE }?.let { response.headers[HttpHeaders.DPoPNonce] }

/** [RFC 9449 9.](https://datatracker.ietf.org/doc/html/rfc9449#section-9) */
private fun resourceServerProvidedNonce(response: HttpResponse): String? =
    response.takeIf {
        response.headers.getAll(HttpHeaders.WWWAuthenticate)?.any { it.contains(USE_DPOP_NONCE) } == true
    }?.let { response.headers[HttpHeaders.DPoPNonce] }
