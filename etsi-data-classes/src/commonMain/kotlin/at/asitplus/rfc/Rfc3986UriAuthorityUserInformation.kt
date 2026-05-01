package at.asitplus.rfc

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class Rfc3986UriAuthorityUserInformation(
    private val percentEncodingAwareString: Rfc3986PercentEncodingAwareString,
) {
    init {
        string.forEachIndexed { index, it ->
            require(it.isUserInformationLikeCharacter()) {
                "Expected user information to satisfy grammar *( unreserved / pct-encoded / sub-delims / \":\" ), but got `$it` at index $index in `$string`"
            }
        }
    }

    constructor(string: String): this(Rfc3986PercentEncodingAwareString(string))

    private val string: String
        get() = percentEncodingAwareString.string

    /**
     * Applications should not render as clear text any data
     *    after the first colon (":") character found within a userinfo
     *    subcomponent unless the data after the colon is the empty string
     *    (indicating no password).
     */
    fun toString(includeSensitiveInformation: Boolean) = if(includeSensitiveInformation) {
        string
    } else {
        val renderUntil = string.indexOf(":").takeIf {
            it != -1
        } ?: string.lastIndex
        string.substring(0..renderUntil)
    }

//    @Suppress("POTENTIALLY_NON_REPORTED_ANNOTATION")
//    @Deprecated("Usage of toString in user information is prohibited as a decision has to be made on whether to include sensitive information or not.", ReplaceWith("toString(includeSensitiveInformation)"))
//    override fun toString() = throw UnsupportedOperationException(
//        "Usage of toString() in user information is prohibited as a decision has to be made on whether to include sensitive information or not. Please use `toString(includeSensitiveInformation)` instead."
//    )

    /**
     *       userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )
     */
    private fun Char.isUserInformationLikeCharacter() = Rfc3986Grammar.isUnreserved(this)
            || Rfc3986Grammar.isPercentEncodedLikeCharacter(this)
            || Rfc3986Grammar.isSubcomponentDelimiter(this)
            || this == ':'
}