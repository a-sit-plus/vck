package at.asitplus.rqes.serializers

import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Deprecated(
    "Module will be removed in the future", ReplaceWith(
        "Base64X509CertificateSerializer",
        imports = ["at.asitplus.csc.serializers.Base64X509CertificateSerializer"]
    )
)
object Base64X509CertificateSerializer : KSerializer<X509Certificate> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Base64X509CertificateSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): X509Certificate =
        X509Certificate.decodeFromByteArray(decoder.decodeString().decodeToByteArray(Base64Strict))
            ?: throw Exception("Invalid Base64 String")

    override fun serialize(encoder: Encoder, value: X509Certificate) {
        encoder.encodeString(value.encodeToDer().encodeToString(Base64Strict))
    }
}
