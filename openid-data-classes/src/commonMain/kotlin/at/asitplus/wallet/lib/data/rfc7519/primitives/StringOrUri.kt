package at.asitplus.wallet.lib.data.rfc7519.primitives

import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 *    StringOrURI
 *       A JSON string value, with the additional requirement that while
 *       arbitrary string values MAY be used, any value containing a ":"
 *       character MUST be a URI [RFC3986].  StringOrURI values are
 *       compared as case-sensitive strings with no transformations or
 *       canonicalizations applied.
 */
@Serializable
@JvmInline
value class StringOrUri(val string: String) {
    init {
        validate(string)
    }

    val uri: UniformResourceIdentifier?
        get() = if(isUri) UniformResourceIdentifier(string) else null

    val isUri: Boolean
        get() = string.isUri

    override fun toString() = "${StringOrUri::class.qualifiedName!!}($string)"

    companion object {
        private val String.isUri: Boolean
            get() = contains(":")

        fun validate(value: String) {
            if (value.isUri) {
                UniformResourceIdentifier(value)
            }
        }

        operator fun invoke(uri: UniformResourceIdentifier) = StringOrUri(uri.string)
    }
}