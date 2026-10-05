package at.asitplus.wallet.lib

import io.ktor.http.*

/**
 * A response to send, whatever the HTTP server stack. [body] is already encoded, e.g. as JSON or JWT, and its media
 * type is set as `Content-Type` in [headers]. Write out [status], every header in [headers] and [body] unchanged.
 */
data class PreparedHttpResponse(
    val status: HttpStatusCode,
    val headers: Headers = Headers.Empty,
    val body: String = "",
)
