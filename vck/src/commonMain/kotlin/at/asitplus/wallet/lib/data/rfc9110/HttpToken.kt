package at.asitplus.wallet.lib.data.rfc9110

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
value class HttpToken(val value: String) {
    companion object {
        fun validate(value: String) {
            if (value.isEmpty()) {
                throw IllegalArgumentException("Argument `value` must must contain at least one character.")
            }

            value.forEach {
                HttpTokenCharacter.validate(it)
            }
        }
    }

    init {
        validate(value)
    }
}