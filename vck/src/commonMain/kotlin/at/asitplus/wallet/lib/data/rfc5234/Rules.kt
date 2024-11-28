package at.asitplus.wallet.lib.data.rfc5234

object Rules {
    fun isAlpha(it: Char) = it in 'a'..'z' || it in 'A'..'Z'
    fun isDigit(it: Char) = it in '0'..'9'
}