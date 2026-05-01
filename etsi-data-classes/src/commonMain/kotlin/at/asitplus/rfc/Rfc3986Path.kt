package at.asitplus.rfc

sealed interface Rfc3986Path {
    fun validate() {
        val string = toString()
        string.forEachIndexed { index, ch ->
            require(Rfc3986Grammar.isPCharLikeCharacter(ch) || ch == '/') {
                "Expected path to consist of pchar and `/`, but got `$ch` at index $index in `$string`."
            }
        }
    }

    fun equalsPath(other: Any?): Boolean {
        if (this === other) return true
        if (other == null) return false

        if (other !is Rfc3986Path) return false

        if (Rfc3986UriPathEmpty.toString() != other.toString()) return false

        return true
    }
}