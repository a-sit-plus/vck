package at.asitplus.rfc

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * https://www.rfc-editor.org/rfc/rfc5646.html
 */
@Serializable
@JvmInline
value class Rfc3986UriSchemeName(
    val caseInsensitiveString: CaseInsensitiveString,
) {
    init {
        val firstLetter = string.first()
        require(Rfc3986Grammar.isAlpha(firstLetter)) {
            "Expected scheme name to start with a letter (a-z, A-Z), but got `$firstLetter` in `$string`"
        }
        string.forEachIndexed { index, it ->
            require(Rfc3986Grammar.isAlpha(it) || Rfc3986Grammar.isDigit(it) || it in "+-.") {
                "Expected scheme name to consist of letters (a-z, A-Z), digits (0-9), `+`, `-` or `.`, but got `$it` at index $index in `$string`"
            }
        }
        require(Regex(REGEX).matches(string)) {
            "Expected scheme name to satisfy regex ^$REGEX\$, but got `$string`."
        }
    }

    companion object {
        const val REGEX = "([a-zA-Z][a-zA-Z0-9+-.]*)"
    }

    object Common {
        val MAILTO = Rfc3986UriSchemeName("mailto")
        val HTTP = Rfc3986UriSchemeName("http")
        val HTTPS = Rfc3986UriSchemeName("https")
    }

    constructor(string: String) : this(CaseInsensitiveString(string))

    val string: String
        get() = caseInsensitiveString.string

    override fun toString() = string
}