package at.asitplus.dif

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object SubmissionRequirementRuleEnumSerializer : KSerializer<SubmissionRequirementRuleEnum> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("SubmissionRequirementRuleEnumSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: SubmissionRequirementRuleEnum) {
        encoder.encodeString(value.text)
    }

    override fun deserialize(decoder: Decoder): SubmissionRequirementRuleEnum =
        SubmissionRequirementRuleEnum.parse(decoder.decodeString())
            ?: SubmissionRequirementRuleEnum.NONE
}