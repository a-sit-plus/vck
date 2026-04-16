package at.asitplus.rfc5234ABNF

// https://www.rfc-editor.org/rfc/rfc5234
object Rfc5234ABNFCore {
    fun Char.isAlpha() = this in 'a'..'z' || this in 'A'..'Z'
    fun Char.isDigit() = this in '0'..'9'
}