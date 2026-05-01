package at.asitplus.rfc

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class Rfc3986AuthorityHostRegisteredName(
    val caseInsensitiveString: CaseInsensitiveString,
): Rfc3986AuthorityHost {
    init {
        string.forEachIndexed { index, ch ->
            Rfc3986Grammar.run {
                require(isUnreserved(ch) || isSubcomponentDelimiter(ch) || isPercentEncodedLikeCharacter(ch)) {
                    "Expected characters of registered names to be unreserved, subcomponent delimiters or percent encoded, but got `${ch}` at index $index in `$string`."
                }
            }
        }
        // making sure percent encoded characters are followed by two hex characters
        // No further equality and hashcode considerations are necessary because value is case-insensitve anyway
        Rfc3986PercentEncodingAwareString(string)
    }

    constructor(string: String) : this(CaseInsensitiveString(string))

    val string: String
        get() = caseInsensitiveString.string

    override fun toString() = string
}