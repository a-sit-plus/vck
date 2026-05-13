package at.asitplus.wallet.sdjwt

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class SvgContentPlaceholder(
    val string: String
) {
    init {
        require(!string.first().isDigit()) {
            "Expected placeholder to start with a letter or `_`, but got: $string"
        }
        string.forEachIndexed { index, it ->
            require(it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '_') {
                "Expected placeholder to consist of alphanumeric characters and underscores, but got character `$it` at index $index: $string"
            }
        }
    }
}
