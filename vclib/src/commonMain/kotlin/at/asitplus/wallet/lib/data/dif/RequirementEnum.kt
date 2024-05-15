package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable(with = RequirementEnumSerializer::class)
enum class RequirementEnum(val text: String) {
    NONE("none"),
    REQUIRED("required"),
    PREFERRED("preferred");

    companion object {
        fun parse(text: String) = entries.firstOrNull { it.text == text }
    }
}