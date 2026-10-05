package at.asitplus.wallet.lib

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.data.MediaTypes
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
