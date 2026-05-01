package at.asitplus.rfc

interface Rfc2234Grammar {
    companion object : Rfc2234Grammar
    fun isAlpha(char: Char) = char in 'a'..'z' || char in 'A'..'Z'
    fun isDigit(char: Char) = char in '0'..'9'
    fun isHexDigit(char: Char) = isDigit(char) || char in 'a'..'f' || char in 'A'..'F'
}