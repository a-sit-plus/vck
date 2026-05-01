package at.asitplus.rfc

data class Rfc3986UriPathNoScheme(
    val percentEncodingAwareString: Rfc3986PercentEncodingAwareString
) : Rfc3986RelativeReferencePath {
    init {
        super.validate()
        require(string.isNotEmpty() && string[0] != '/') {
            "Expected path to start with a non-empty segment, but got `$string`."
        }
        string.indexOf(':').takeIf {
            it != -1
        }?.let {
            // if there is a colon, it must not be in the first segment
            // in particular, there must be at least 2 segments and therefore at least 1 `/`
            require(string.indexOf('/') > it) {
                "Expected first segment to not contain a colon, `$string`."
            }
        }
    }

    constructor(string: String) : this(Rfc3986PercentEncodingAwareString(string))

    val string: String
        get() = percentEncodingAwareString.string

    override fun toString() = string

    override fun equals(other: Any?) = equalsPath(other)

    override fun hashCode() = toString().hashCode()
}