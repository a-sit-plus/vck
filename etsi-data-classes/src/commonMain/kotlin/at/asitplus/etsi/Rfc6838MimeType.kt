package at.asitplus.etsi

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = Rfc6838MimeType.InlineSerializer::class)
data class Rfc6838MimeType(
    val string: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Rfc6838MimeType

        return string.compareTo(other.string, ignoreCase = true) == 0
    }

    /**
     * If ignoreCase is true, the result of Char.uppercaseChar().lowercaseChar() on each character is compared.
     */
    override fun hashCode() = string.uppercase().lowercase().hashCode()

    class InlineSerializer : KSerializer<Rfc6838MimeType> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = InlineSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING
            )

        override fun serialize(encoder: Encoder, value: Rfc6838MimeType) {
            encoder.encodeString(value.string)
        }

        override fun deserialize(decoder: Decoder): Rfc6838MimeType {
            return Rfc6838MimeType(decoder.decodeString())
        }
    }
}
