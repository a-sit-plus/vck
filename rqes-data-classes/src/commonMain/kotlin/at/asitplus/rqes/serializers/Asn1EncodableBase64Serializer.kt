package at.asitplus.rqes.serializers

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.encoding.parse
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object Asn1EncodableBase64Serializer : KSerializer<Asn1Element> {
    override val descriptor = PrimitiveSerialDescriptor("Asn1Encodable", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Asn1Element =
        Asn1Element.parse(decoder.decodeString().decodeToByteArray(Base64()))

    override fun serialize(encoder: Encoder, value: Asn1Element) {
        encoder.encodeString(value.derEncoded.encodeToString(Base64()))
    }

}