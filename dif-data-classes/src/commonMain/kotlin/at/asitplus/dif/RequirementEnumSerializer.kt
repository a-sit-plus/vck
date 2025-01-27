package at.asitplus.dif

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object RequirementEnumSerializer : KSerializer<RequirementEnum> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(
            "PresentationDefinitionRequirementEnumSerializer",
            PrimitiveKind.STRING
        )

    override fun serialize(encoder: Encoder, value: RequirementEnum) {
        encoder.encodeString(value.text)
    }

    override fun deserialize(decoder: Decoder): RequirementEnum =
        RequirementEnum.parse(decoder.decodeString()) ?: RequirementEnum.NONE
}