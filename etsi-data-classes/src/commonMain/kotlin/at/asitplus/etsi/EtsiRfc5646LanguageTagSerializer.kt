package at.asitplus.etsi

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

class EtsiRfc5646LanguageTagSerializer : KSerializer<Rfc5646LanguageTag> {
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
        decoder.decodeString().also {
            require(it.lowercase() == it) {
                "Expected language tag to be lowercase for ETSI compliance, but was $it"
            }
        }
    )
}