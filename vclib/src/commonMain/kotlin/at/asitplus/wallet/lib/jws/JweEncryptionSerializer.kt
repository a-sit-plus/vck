package at.asitplus.wallet.lib.jws

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object JweEncryptionSerializer : KSerializer<JweEncryption?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JweEncryptionSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JweEncryption?) {
        value?.let { encoder.encodeString(it.text) }
    }

    override fun deserialize(decoder: Decoder): JweEncryption? {
        val decoded = decoder.decodeString()
        return JweEncryption.values().firstOrNull { it.text == decoded }
    }
}