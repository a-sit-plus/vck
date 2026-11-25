package at.asitplus.wallet.ios

import kotlin.coroutines.cancellation.CancellationException
import at.asitplus.signum.internals.CoreFoundationException
import platform.Foundation.NSError

/** Throwable is explicit: Swift errors become ObjCErrorException inside Kotlin. */
object SuspendFunctionBridge {
    @Throws(Throwable::class)
    suspend fun call0(function: suspend () -> Any?): Any? = function()

    @Throws(Throwable::class)
    suspend fun call1(function: suspend (Any?) -> Any?, argument: Any?): Any? = function(argument)

    @Throws(Throwable::class)
    suspend fun call2(function: suspend (Any?, Any?) -> Any?, first: Any?, second: Any?): Any? =
        function(first, second)
}

object SwiftErrorBridge {
    fun fromError(error: NSError): Throwable = CoreFoundationException(error)

    @Throws(Throwable::class)
    fun rethrow(cause: Throwable) { throw cause }

    @Throws(CancellationException::class)
    fun cancellation() { throw CancellationException("Swift callback cancelled") }
}
