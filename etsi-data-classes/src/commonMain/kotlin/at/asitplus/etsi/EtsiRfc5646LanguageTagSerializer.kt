package at.asitplus.etsi

import io.github.aakira.napier.Napier
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

class EtsiRfc5646LanguageTagSerializer : KSerializer<Rfc5646LanguageTag> {
    /** Serialization descriptor for a lowercase RFC 5646 language-tag string (TS 119 612, 5.1.4). */
    override val descriptor: SerialDescriptor
        get() = PrimitiveSerialDescriptor(
            serialName = EtsiRfc5646LanguageTagSerializer::class.qualifiedName!!,
            kind = PrimitiveKind.STRING,
        )

    override fun serialize(
        encoder: Encoder,
        value: Rfc5646LanguageTag
    ) {
        encoder.encodeString(value.string.lowercase())
    }

    override fun deserialize(decoder: Decoder) = Rfc5646LanguageTag(
        decoder.decodeString().let { decodedLanguageTag ->
            decodedLanguageTag.lowercase().also { normalizedLanguageTag ->
                if (normalizedLanguageTag != decodedLanguageTag) {
                    Napier.w("Expected language tag to be lowercase for ETSI compliance, but was $decodedLanguageTag")
                }
            }
        }
    )
}
