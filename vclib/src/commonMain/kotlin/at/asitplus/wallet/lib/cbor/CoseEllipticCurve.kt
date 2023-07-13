package at.asitplus.wallet.lib.cbor

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = CoseEllipticCurveSerializer::class)
enum class CoseEllipticCurve(val value: Int) {

    P256(1),
    P384(2),
    P521(3),
    X25519(4),
    X448(5),
    Ed25519(6),
    Ed448(7);

}

object CoseEllipticCurveSerializer : KSerializer<CoseEllipticCurve?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CoseEllipticCurveSerializer", PrimitiveKind.INT)

    override fun serialize(encoder: Encoder, value: CoseEllipticCurve?) {
        value?.let { encoder.encodeInt(it.value) }
    }

    override fun deserialize(decoder: Decoder): CoseEllipticCurve? {
        val decoded = decoder.decodeInt()
        return CoseEllipticCurve.values().firstOrNull { it.value == decoded }
    }
}