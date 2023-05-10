package at.asitplus.wallet.lib.oidc

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object IdTokenTypeSerializer : KSerializer<IdTokenType?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("IdTokenTypeSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: IdTokenType?) {
        value?.let { encoder.encodeString(it.text) }
    }

    override fun deserialize(decoder: Decoder): IdTokenType? {
        val decoded = decoder.decodeString()
        return IdTokenType.values().firstOrNull { it.text == decoded }
    }
}