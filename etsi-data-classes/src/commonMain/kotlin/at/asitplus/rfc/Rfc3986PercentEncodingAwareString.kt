package at.asitplus.rfc

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = Rfc3986PercentEncodingAwareString.InlineSerializer::class)
data class Rfc3986PercentEncodingAwareString(
    val string: String
) {
    init {
        requirePercentEncodingConsistence(string)
    }

    class InlineSerializer : KSerializer<Rfc3986PercentEncodingAwareString> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = InlineSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: Rfc3986PercentEncodingAwareString
        ) {
            encoder.encodeString(value.string)
        }

        override fun deserialize(decoder: Decoder) = Rfc3986PercentEncodingAwareString(
            decoder.decodeString()
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Rfc3986PercentEncodingAwareString

        return string.percentEncodedUppercaseListRepresentation().joinToString("%").compareTo(
            other.string.percentEncodedUppercaseListRepresentation().joinToString("%")
        ) == 0
    }

    override fun hashCode() = string.percentEncodedUppercaseListRepresentation().hashCode()

    override fun toString() = string

    companion object {
        fun requirePercentEncodingConsistence(string: String) {
            val percentIndices = string.mapIndexedNotNull { index, char ->
                index.takeIf {
                    char == '%'
                }
            }
            percentIndices.forEach { index ->
                string.substring((index + 1)..(index + 2)).forEachIndexed { index2, it ->
                    require(Rfc3986Grammar.isHexDigit(it)) {
                        "Expected percent encoded character to be represented by hexadecimal digits (0-9, a-f, A-F), but got `$it` at index ${index + 1 + index2} in `$string`"
                    }
                }
            }
        }
    }

    private fun String.percentEncodedUppercaseListRepresentation() = split("%").mapIndexed { index, string ->
        if (index == 0) {
            string
        } else {
            string.substring(0, 2).uppercase() + string.substring(2)
        }
    }
}