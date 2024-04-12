package at.asitplus.wallet.lib.data.JSONPath

fun String.isLexicographicallySmallerThan(other: String): Boolean {
    return if (this.isEmpty()) {
        other.isNotEmpty()
    } else if (other.isEmpty()) {
        false
    } else if (this[0] < other[0]) {
        true
    } else {
        (this[0] == other[0]) and this.substring(1)
            .isLexicographicallySmallerThan(other.substring(1))
    }
}