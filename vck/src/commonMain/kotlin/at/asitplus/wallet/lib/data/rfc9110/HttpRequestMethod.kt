package at.asitplus.wallet.lib.data.rfc9110

import kotlin.jvm.JvmInline

/**
 * https://www.iana.org/assignments/http-methods/http-methods.xhtml
 */
@JvmInline
value class HttpRequestMethod(val value: String) {
    init {
        validate(value)
    }

    companion object {
        fun validate(value: String) {
            // TODO: maybe build somewhere from IANA registry: https://www.iana.org/assignments/http-methods/http-methods.xhtml
        }
        val Head = HttpRequestMethod(Registry.HEAD)
        val Get = HttpRequestMethod(Registry.GET)
        val Post = HttpRequestMethod(Registry.POST)
        val Put = HttpRequestMethod(Registry.PUT)
    }
    object Registry {
        const val GET = "GET"
        const val HEAD = "HEAD"
        const val POST = "POST"
        const val PUT = "PUT"
        // ...
        // TODO: maybe build somewhere from IANA registry: https://www.iana.org/assignments/http-methods/http-methods.xhtml
    }
}