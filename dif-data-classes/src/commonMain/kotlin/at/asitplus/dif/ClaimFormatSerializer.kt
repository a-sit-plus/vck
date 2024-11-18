package at.asitplus.dif

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object ClaimFormatSerializer : KSerializer<ClaimFormat> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ClaimFormatSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ClaimFormat) {
        encoder.encodeString(value.text)
    }

    override fun deserialize(decoder: Decoder): ClaimFormat {
        return ClaimFormat.parse(decoder.decodeString()) ?: ClaimFormat.NONE
    }
}