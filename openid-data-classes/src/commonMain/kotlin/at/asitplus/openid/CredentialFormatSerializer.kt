package at.asitplus.openid

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object CredentialFormatSerializer : KSerializer<CredentialFormatEnum> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CredentialFormatEnumSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: CredentialFormatEnum) {
        encoder.encodeString(value.text)
    }

    override fun deserialize(decoder: Decoder): CredentialFormatEnum {
        return CredentialFormatEnum.parse(decoder.decodeString()) ?: CredentialFormatEnum.NONE
    }
}