package at.asitplus.wallet.lib.data.rfc9110

import at.asitplus.wallet.lib.data.rfc5234.Rules
import kotlin.jvm.JvmInline

/**
 *  5.6.2. Tokens
 *
 * Tokens are short textual identifiers that do not include whitespace or delimiters.
 *
 *   token          = 1*tchar
 *
 *   tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
 *                  / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
 *                  / DIGIT / ALPHA
 *                  ; any VCHAR, except delimiters
 *
 * Many HTTP field values are defined using common syntax components, separated by whitespace or
 * specific delimiting characters. Delimiters are chosen from the set of US-ASCII visual characters
 * not allowed in a token (DQUOTE and "(),/:;<=>?@[\]{}").
 */
@JvmInline
internal value class HttpTokenCharacter(val value: Char) {
    companion object {
        private const val allowedSpecialCharacters = "!#\$%&'*+-.^_`|~"
        fun validate(value: Char) {
            if (!(value in allowedSpecialCharacters || Rules.isAlpha(value) || Rules.isDigit(value))) {
                throw IllegalArgumentException("Argument `value` must be a digit (0..9), a letter (a..z or A..Z) or an allowed special character ($allowedSpecialCharacters).")
            }
        }
    }

    init {
        validate(value)
    }
}