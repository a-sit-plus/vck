package at.asitplus.openid

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object IdTokenTypeSerializer : KSerializer<IdTokenType> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("IdTokenType", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: IdTokenType) {
        encoder.encodeString(value.text)
    }

    override fun deserialize(decoder: Decoder): IdTokenType {
        val decoded = decoder.decodeString()
        return IdTokenType.entries.first { it.text == decoded }
    }
}
