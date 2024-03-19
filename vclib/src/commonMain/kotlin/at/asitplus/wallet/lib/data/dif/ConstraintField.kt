package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class ConstraintField(
    @SerialName("id")
    val id: String? = null,
    @SerialName("purpose")
    val purpose: String? = null,
    @SerialName("predicate")
    val predicate: RequirementEnum? = null,
    @SerialName("path")
    // should be JSONPath
    val path: List<String>,
    @SerialName("filter")
    val filter: ConstraintFilter? = null,
    @SerialName("intent_to_retain")
    val intentToRetain: Boolean? = null,
)