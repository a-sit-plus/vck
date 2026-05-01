package at.asitplus.rfc

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class Rfc3986UriQuery(
    /**
     *    query         = *( pchar / "/" / "?" )
     */
    val percentEncodingAwareString: Rfc3986PercentEncodingAwareString,
) {
    init {
        string.forEachIndexed { index, it ->
            require(Rfc3986Grammar.isPCharLikeCharacter(it) || it in "/?") {
                "Expected query to consist of pchar, `/` and `?`, but got `$it` at index $index in `$string`"
            }
        }
    }

    constructor(string: String) : this(Rfc3986PercentEncodingAwareString(string))

    val string: String
        get() = percentEncodingAwareString.string

    override fun toString() = string
}
