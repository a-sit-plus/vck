package at.asitplus.wallet.lib.data.rfc3986

import io.ktor.http.Url
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * specification: https://www.rfc-editor.org/rfc/rfc3986
 */
@Serializable(with = UriInlineSerializer::class)
@JvmInline value class Uri(val value: String) {
    companion object {
        fun validate(value: String) {
            // TODO, or possibly replace if existing implementation is found
        }
    }

    init {
        validate(value)
    }

    override fun toString() = value
}

