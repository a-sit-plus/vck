package at.asitplus.csc.api.serializers

import at.asitplus.signum.indispensable.decodeFromDer
import at.asitplus.signum.indispensable.encodeToDer
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.pki.Certificate
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object Base64X509CertificateSerializer : KSerializer<Certificate> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Base64X509CertificateSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Certificate =
        Certificate.decodeFromDer(decoder.decodeString().decodeToByteArray(Base64Strict))

    override fun serialize(encoder: Encoder, value: Certificate) {
        encoder.encodeString(value.encodeToDer().encodeToString(Base64Strict))
    }
}
