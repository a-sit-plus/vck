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
    val fromNested: Collection<SubmissionRequirement>? = null,
)