package at.asitplus.wallet.lib.jws

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object JwsContentTypeSerializer : KSerializer<JwsContentType?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsContentTypeSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsContentType?) {
        value?.let { encoder.encodeString(it.text) }
    }

    override fun deserialize(decoder: Decoder): JwsContentType? {
        val decoded = decoder.decodeString()
        return JwsContentType.values().firstOrNull { it.text == decoded }
    }

}