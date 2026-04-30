package at.asitplus.etsi

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
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
    }

    constructor(string: String) : this(CaseInsensitiveString(string))
    val string: String
        get() = caseInsensitiveString.string

    override fun toString() = string
}