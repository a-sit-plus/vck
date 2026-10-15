package at.asitplus.wallet.lib

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.data.MediaTypes
import io.ktor.http.*

/**
 * A response to send, whatever the HTTP server stack. Write out [status], every header in [headers], and [body]
 * unchanged with its [HttpBody.contentType] as `Content-Type`; [headers] never contain `Content-Type`.
 */
data class PreparedHttpResponse(
    val status: HttpStatusCode,
    val headers: Headers = Headers.Empty,
    val body: HttpBody? = null,
) {
    init {
        headers.requireNoContentType()
    }
}

/** A response with [value] as JSON body, with [status], and the headers from [extraHeaders]. */
internal inline fun <reified T> jsonHttpResponse(
    value: T,
    status: HttpStatusCode = HttpStatusCode.OK,
    extraHeaders: HeadersBuilder.() -> Unit = {},
) = PreparedHttpResponse(
    status = status,
    headers = Headers.build(extraHeaders),
    body = HttpBody(ContentType.Application.Json, joseCompliantSerializer.encodeToString(value)),
)

/**
 * Whether the `Accept` header [acceptHeader] asks for [mediaType] instead of JSON, i.e. lists [mediaType] explicitly,
 * with a quality not below the one of `application/json` (or `application/*`, `*/*`).
 * Wildcards alone never select [mediaType], as JSON is the representation every client understands.
 */
internal fun acceptsOverJson(acceptHeader: String?, mediaType: String): Boolean {
    val accepted = parseHeaderValue(acceptHeader).associate { it.value.trim().lowercase() to it.quality }
    val quality = accepted[mediaType] ?: return false
    val jsonQuality = accepted[MediaTypes.Application.JSON]
        ?: accepted["application/*"]
        ?: accepted["*/*"]
        ?: 0.0
    return quality > 0.0 && quality >= jsonQuality
}
