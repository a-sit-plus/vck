package at.asitplus.etsi

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * https://www.rfc-editor.org/rfc/rfc5646.html
 */
@Serializable(with = Rfc5646LanguageTag.InlineSerializer::class)
data class Rfc5646LanguageTag(
    val string: String,
) {
    init {
        // TODO: implement proper grammar validation?
    }

    /**
     *    At all times, language tags and their subtags, including private use
     *    and extensions, are to be treated as case insensitive: there exist
     *    conventions for the capitalization of some of the subtags, but these
     *    MUST NOT be taken to carry meaning.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Rfc5646LanguageTag

        return string.equals(other.string, ignoreCase = true)
    }

    override fun hashCode() = string.lowercase().hashCode()

    class InlineSerializer : KSerializer<Rfc5646LanguageTag> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = InlineSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: Rfc5646LanguageTag
        ) {
            encoder.encodeString(value.string.lowercase())
        }

        override fun deserialize(decoder: Decoder) = Rfc5646LanguageTag(
            decoder.decodeString()
        )
    }
}


