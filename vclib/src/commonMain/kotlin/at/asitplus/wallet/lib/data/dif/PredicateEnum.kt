package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.Serializable


/**
 * Data class for
 * [DIF Presentation Exchange v2.0.0](https://identity.foundation/presentation-exchange/spec/v2.0.0/#predicate-feature)
 */
@Serializable(with = PredicateEnumSerializer::class)
enum class PredicateEnum(val text: String) {
    REQUIRED("required"),
    PREFERRED("preferred");

    companion object {
        fun parse(text: String) = entries.firstOrNull { it.text == text }
    }
}