package at.asitplus.rfc

import kotlin.jvm.JvmInline

data class Rfc3986UriPathRootless(
    val percentEncodingAwareString: Rfc3986PercentEncodingAwareString,
) : Rfc3986UriPath {
    init {
        super.validate()
        require(string.isNotEmpty() && string[0] != '/') {
            "Expected path to start with a non-empty segment, but got `$string`."
        }
    }

    constructor(string: String) : this(Rfc3986PercentEncodingAwareString(string))

    val string: String
        get() = percentEncodingAwareString.string

    override fun toString() = string

    override fun equals(other: Any?) = equalsPath(other)

    override fun hashCode() = toString().hashCode()
}