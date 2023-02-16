package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class SubmissionRequirement(
    @SerialName("name")
    val name: String? = null,
    @SerialName("purpose")
    val purpose: String? = null,
    @SerialName("rule")
    val rule: SubmissionRequirementRuleEnum? = null,
    @SerialName("count")
    val count: Int? = null,
    @SerialName("min")
    val min: Int? = null,
    @SerialName("max")
    val max: Int? = null,
    @SerialName("from")
    val from: String? = null,
    @SerialName("from_nested")
    val fromNested: Array<SubmissionRequirement>? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SubmissionRequirement

        if (name != other.name) return false
        if (purpose != other.purpose) return false
        if (rule != other.rule) return false
        if (count != other.count) return false
        if (min != other.min) return false
        if (max != other.max) return false
        if (from != other.from) return false
        if (fromNested != null) {
            if (other.fromNested == null) return false
            if (!fromNested.contentEquals(other.fromNested)) return false
        } else if (other.fromNested != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = name?.hashCode() ?: 0
        result = 31 * result + (purpose?.hashCode() ?: 0)
        result = 31 * result + (rule?.hashCode() ?: 0)
        result = 31 * result + (count ?: 0)
        result = 31 * result + (min ?: 0)
        result = 31 * result + (max ?: 0)
        result = 31 * result + (from?.hashCode() ?: 0)
        result = 31 * result + (fromNested?.contentHashCode() ?: 0)
        return result
    }
}