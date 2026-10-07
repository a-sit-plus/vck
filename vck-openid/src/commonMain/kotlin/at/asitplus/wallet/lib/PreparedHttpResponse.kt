package at.asitplus.wallet.lib

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
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

/** A response with [value] as JSON body, with [status], and the headers from [extraHeaders]. */
internal inline fun <reified T> jsonHttpResponse(
    value: T,
    status: HttpStatusCode = HttpStatusCode.OK,
    extraHeaders: HeadersBuilder.() -> Unit = {},
) = PreparedHttpResponse(
    status = status,
    headers = Headers.build {
        append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        extraHeaders()
    },
    body = joseCompliantSerializer.encodeToString(value),
)
