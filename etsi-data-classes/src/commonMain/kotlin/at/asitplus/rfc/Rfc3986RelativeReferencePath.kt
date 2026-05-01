package at.asitplus.rfc

sealed interface Rfc3986RelativeReferencePath : Rfc3986Path {
    companion object {
        /**
         *      relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
         *
         *      relative-part = "//" authority path-abempty
         *                     / path-absolute
         *                     / path-noscheme
         *                     / path-empty
         */
        operator fun invoke(
            string: String,
            hasAuthority: Boolean,
        ) = when {
            hasAuthority -> Rfc3986UriPathAbsoluteOrEmpty(string)
            string.isEmpty() -> Rfc3986UriPathEmpty
            string.startsWith("/") -> Rfc3986UriPathAbsolute(string)
            else -> Rfc3986UriPathNoScheme(string)
        }
    }
}