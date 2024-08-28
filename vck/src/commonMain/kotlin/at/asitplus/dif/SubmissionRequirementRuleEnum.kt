package at.asitplus.dif

import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable(with = SubmissionRequirementRuleEnumSerializer::class)
enum class SubmissionRequirementRuleEnum(val text: String) {
    NONE("none"),
    PICK("pick"),
    ALL("all");

    companion object {
        fun parse(text: String) = values().firstOrNull { it.text == text }
    }
}