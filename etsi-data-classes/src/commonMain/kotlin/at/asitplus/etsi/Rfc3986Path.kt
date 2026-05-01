package at.asitplus.etsi

sealed interface Rfc3986Path {
    fun validate() {
        val string = toString()
        string.forEachIndexed { index, ch ->
            require(Rfc3986Grammar.isPCharLikeCharacter(ch) || ch == '/') {
                "Expected path to consist of pchar and `/`, but got `$ch` at index $index in `$string`."
            }
        }
    }
}