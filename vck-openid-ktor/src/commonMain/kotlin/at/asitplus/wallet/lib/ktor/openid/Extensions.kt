package at.asitplus.wallet.lib.ktor.openid

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async

fun <T> CoroutineScope.lazyDeferred(
    block: suspend CoroutineScope.() -> T,
): Lazy<Deferred<T>> = lazy {
    async(start = CoroutineStart.LAZY) { block() }
}
