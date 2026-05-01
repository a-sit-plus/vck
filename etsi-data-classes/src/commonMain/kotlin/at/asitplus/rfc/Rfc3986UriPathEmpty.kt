package at.asitplus.rfc

object Rfc3986UriPathEmpty : Rfc3986UriPath, Rfc3986RelativeReferencePath {
    override fun toString() = ""

    override fun equals(other: Any?) = equalsPath(other)

    override fun hashCode() = toString().hashCode()
}