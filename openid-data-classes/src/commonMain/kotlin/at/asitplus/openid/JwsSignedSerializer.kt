package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JwsSigned
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object JwsSignedSerializer : KSerializer<JwsSigned> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsSignedSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): JwsSigned = JwsSigned.deserialize(decoder.decodeString()).getOrThrow()

    override fun serialize(encoder: Encoder, value: JwsSigned) {
        encoder.encodeString(value.serialize())
    }
}