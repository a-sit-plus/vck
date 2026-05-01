package at.asitplus.rfc

sealed interface Rfc3986UriReference {
    val schemeName: Rfc3986UriSchemeName?
    val authority: Rfc3986Authority?
    val path: Rfc3986Path
    val query: Rfc3986UriQuery?
    val fragment: Rfc3986UriFragment?

    // TODO: implement resolving uri references with respect to a given base uri?

    companion object {
        operator fun invoke(string: String): Rfc3986UriReference {
            val partRegex = Regex("""^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?""")
            val match = partRegex.matchEntire(string)
            require(match != null) {
                "Expected string to be a valid URI reference, but tokenization itself failed for input `$string`."
            }

            val authority = match.groups[4]?.value?.let {
                Rfc3986Authority(it)
            }
            val path = match.groups[5]?.value ?: throw IllegalArgumentException(
                "Expected URI reference to contain a path, but none was found."
            )
            val query = match.groups[7]?.value?.let(::Rfc3986UriQuery)
            val fragment = match.groups[9]?.value?.let(::Rfc3986UriFragment)

            val scheme = match.groups[2]?.value?.let(::Rfc3986UriSchemeName)

            if (scheme == null) {
                return Rfc3986RelativeReference(
                    authority = authority,
                    path = Rfc3986RelativeReferencePath(
                        path,
                        hasAuthority = authority != null
                    ),
                    query = query,
                    fragment = fragment,
                )
            } else {
                return Rfc3986UniformResourceIdentifier(
                    schemeName = scheme,
                    authority = authority,
                    path = Rfc3986UriPath(
                        path,
                        hasAuthority = authority != null
                    ),
                    query = query,
                    fragment = fragment,
                )
            }
        }
    }
}