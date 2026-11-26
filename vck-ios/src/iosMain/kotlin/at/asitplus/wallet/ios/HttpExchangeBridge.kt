package at.asitplus.wallet.ios

import at.asitplus.signum.internals.toNSData
import at.asitplus.wallet.lib.HttpExchange
import at.asitplus.wallet.lib.HttpStep
import at.asitplus.wallet.lib.ProtocolRequest
import at.asitplus.wallet.lib.ReceivedHttpResponse
import io.ktor.http.Headers
import io.ktor.http.HttpStatusCode
import platform.Foundation.NSData

/** A [ProtocolRequest] flattened to Foundation types, to be sent with `URLSession`. */
class SwiftHttpRequest internal constructor(
    val url: String,
    val method: String,
    /** Values of repeated headers are joined with `, ` (RFC 9110, 5.3). */
    val headers: Map<String, String>,
    val contentType: String?,
    val body: NSData?,
)

/**
 * Sends one request and returns the response without following redirects, which VC-K treats as errors.
 * Implemented in Swift by `URLSessionTransport`.
 */
interface HttpTransport {
    @Throws(Throwable::class)
    suspend fun send(request: SwiftHttpRequest): ReceivedHttpResponse
}

/** Runs this exchange from Kotlin, sending its requests with [transport]. */
internal suspend fun <T> HttpExchange<T>.execute(transport: HttpTransport): T {
    var step = next(null).getOrThrow()
    while (step is HttpStep.Send) {
        step = next(transport.send(HttpExchangeBridge.request(step.request))).getOrThrow()
    }
    return (step as HttpStep.Done).value
}

/** Converts VC-K's transport-agnostic HTTP types, whose ktor types Swift cannot easily build or read. */
object HttpExchangeBridge {
    fun request(request: ProtocolRequest): SwiftHttpRequest = with(request.http) {
        SwiftHttpRequest(
            url = url,
            method = method.value,
            headers = headers.entries().associate { (name, values) -> name to values.joinToString(", ") },
            contentType = body?.contentType?.toString(),
            body = body?.text?.encodeToByteArray()?.toNSData(),
        )
    }

    fun response(status: Int, headers: Map<String, String>, body: String): ReceivedHttpResponse =
        ReceivedHttpResponse(
            status = HttpStatusCode.fromValue(status),
            headers = Headers.build { headers.forEach { (name, value) -> append(name, value) } },
            body = body,
        )
}
