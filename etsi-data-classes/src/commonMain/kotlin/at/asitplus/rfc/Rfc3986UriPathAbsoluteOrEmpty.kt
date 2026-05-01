package at.asitplus.rfc

data class Rfc3986UriPathAbsoluteOrEmpty(
    val percentEncodingAwareString: Rfc3986PercentEncodingAwareString,
) : Rfc3986UriPath, Rfc3986RelativeReferencePath {
    init {
        super<Rfc3986UriPath>.validate()
        super<Rfc3986RelativeReferencePath>.validate()
        require(string.isEmpty() || string.startsWith("/")) {
            "Expected path to be empty or start with `/`, but got `$string`."
        }
    }

    constructor(string: String) : this(Rfc3986PercentEncodingAwareString(string))

    val string: String
        get() = percentEncodingAwareString.string

    override fun toString() = string

    override fun equals(other: Any?) = equalsPath(other)

    override fun hashCode() = toString().hashCode()
}