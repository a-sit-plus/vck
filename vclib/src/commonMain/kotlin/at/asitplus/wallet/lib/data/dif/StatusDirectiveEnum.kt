package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable(with = StatusDirectiveEnumSerializer::class)
enum class StatusDirectiveEnum(val text: String) {
    NONE("none"),
    REQUIRED("required"),
    ALLOWED("allowed"),
    DISALLOWED("disallowed");

    companion object {
        fun parse(text: String) = values().firstOrNull { it.text == text }
    }
}