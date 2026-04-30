package at.asitplus.etsi

sealed interface Rfc3986UriPath {
    fun validate() {
        val string = toString()
        string.forEachIndexed { index, ch ->
            require(Rfc3986Grammar.isPCharLikeCharacter(ch) || ch == '/') {
                "Expected path to consist of pchar and `/`, but got `$ch` at index $index in `$string`."
            }
        }
    }

    companion object {
        operator fun invoke(string: String) = when {
            string.isEmpty() -> Rfc3986UriPathEmpty
            string.startsWith("/") -> Rfc3986UriPathAbsolute(string)
            else -> Rfc3986UriPathRootless(string)
        }
    }
}