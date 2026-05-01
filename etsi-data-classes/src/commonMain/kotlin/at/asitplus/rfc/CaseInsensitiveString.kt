package at.asitplus.rfc

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = CaseInsensitiveString.InlineSerializer::class)
data class CaseInsensitiveString(
    val string: String
) {
    class InlineSerializer : KSerializer<CaseInsensitiveString> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = InlineSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: CaseInsensitiveString
        ) {
            encoder.encodeString(value.string)
        }

        override fun deserialize(decoder: Decoder) = CaseInsensitiveString(
            decoder.decodeString()
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CaseInsensitiveString

        return string.equals(other.string, ignoreCase = true)
    }

    override fun hashCode() = string.uppercase().lowercase().hashCode()

    override fun toString() = string
}