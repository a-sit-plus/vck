package at.asitplus.iso

import at.asitplus.catching
import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier

/**
 * Serializes an authority-based origin string as defined in
 * https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin.
 * Opaque origins, such as Android application origins, cannot be serialized this way.
 */
fun String.serializeOrigin(): String? = catching {
    val uri = Rfc3986UniformResourceIdentifier(this)
    val authority = uri.authority ?: return@catching null

    val url = io.ktor.http.Url(this)
    if (url.host.isBlank()) return@catching null
    val scheme = uri.schemeName.toString().lowercase()
    val host = url.host.lowercase()
    val port = authority.port
    buildString {
        append(scheme)
        append("://")
        append(host)
        if (port != null && port != scheme.defaultPort()) {
            append(":")
            append(port.toString())
        }
    }
}.getOrNull()

// https://url.spec.whatwg.org/#special-scheme
private fun String.defaultPort(): ULong? = when (this) {
    "ftp" -> 21u
    "http", "ws" -> 80u
    "https", "wss" -> 443u
    else -> null
}
