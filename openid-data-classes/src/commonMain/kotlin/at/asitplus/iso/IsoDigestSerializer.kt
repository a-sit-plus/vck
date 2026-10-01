package at.asitplus.iso

import at.asitplus.signum.indispensable.Digest
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/** Part of the ISO/IEC 18013-5:2021 standard: Message digest function (9.1.2.5) */
object IsoDigestSerializer : KSerializer<Digest> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("IsoDigest", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Digest =
        decoder.decodeString().toDigest()

    override fun serialize(
        encoder: Encoder,
        value: Digest,
    ): Unit {
        encoder.encodeString(value.toIsoString())
    }

}

/** Part of the ISO/IEC 18013-5:2021 standard: Message digest function (9.1.2.5) */
fun Digest.toIsoString(): String = when (this) {
    Digest.SHA256 -> "SHA-256"
    Digest.SHA384 -> "SHA-384"
    Digest.SHA512 -> "SHA-512"
    else -> throw IllegalArgumentException("Digest not supported in ISO 18013-5: $this")
}

/** Part of the ISO/IEC 18013-5:2021 standard: Message digest function (9.1.2.5) */
fun String.toDigest(): Digest = when (this) {
    "SHA-256" -> Digest.SHA256
    "SHA-384" -> Digest.SHA384
    "SHA-512" -> Digest.SHA512
    else -> throw IllegalArgumentException("Digest value not supported in ISO 18013-5: $this")
}
