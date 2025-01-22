package at.asitplus.dif

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object StatusDirectiveEnumSerializer : KSerializer<StatusDirectiveEnum> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(
            "PresentationDefinitionStatusDirectiveEnumSerializer",
            PrimitiveKind.STRING
        )

    override fun serialize(encoder: Encoder, value: StatusDirectiveEnum) {
        encoder.encodeString(value.text)
    }

    override fun deserialize(decoder: Decoder): StatusDirectiveEnum =
        StatusDirectiveEnum.parse(decoder.decodeString()) ?: StatusDirectiveEnum.NONE
}