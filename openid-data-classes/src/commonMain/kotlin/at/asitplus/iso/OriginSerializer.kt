package at.asitplus.iso

import at.asitplus.catching

/**
 * Serializes an origin string as defined in
 * https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin.
 */
fun String.serializeOrigin(): String? = catching {
    // Use Ktor URL for parsing; treat missing/empty host as opaque
    val url = io.ktor.http.Url(this)
    if (url.host.isBlank()) return@catching null
    val scheme = url.protocol.name
    val host = url.host
    val defaultPort = url.protocol.defaultPort
    val port = url.port
    buildString {
        append(scheme)
        append("://")
        append(host)
        if (port != defaultPort) {
            append(":")
            append(port)
        }
    }
}.getOrNull()
