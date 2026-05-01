package at.asitplus.rfc

sealed interface Rfc3986UriPath : Rfc3986Path {
    companion object {
        /**
         *       URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
         *
         *       hier-part   = "//" authority path-abempty
         *                   / path-absolute
         *                   / path-rootless
         *                   / path-empty
         */
        operator fun invoke(
            string: String,
            hasAuthority: Boolean,
        ) = when {
            hasAuthority -> Rfc3986UriPathAbsoluteOrEmpty(string)
            string.isEmpty() -> Rfc3986UriPathEmpty
            string.startsWith("/") -> Rfc3986UriPathAbsolute(string)
            else -> Rfc3986UriPathRootless(string)
        }
    }
}

