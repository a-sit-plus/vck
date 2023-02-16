package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object ClaimFormatEnumSerializer : KSerializer<ClaimFormatEnum> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ClaimFormatEnumSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ClaimFormatEnum) {
        encoder.encodeString(value.text)
    }

    override fun deserialize(decoder: Decoder): ClaimFormatEnum {
        return ClaimFormatEnum.parse(decoder.decodeString()) ?: ClaimFormatEnum.NONE
    }
}