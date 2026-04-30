package at.asitplus.etsi

import kotlin.jvm.JvmInline

@JvmInline
value class Rfc3986UriPathRootless(
    val percentEncodingAwareString: Rfc3986PercentEncodingAwareString
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
}