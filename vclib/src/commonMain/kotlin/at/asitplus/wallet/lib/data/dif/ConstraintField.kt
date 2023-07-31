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
    val path: Array<String>,
    @SerialName("filter")
    val filter: ConstraintFilter? = null,
    @SerialName("intent_to_retain")
    val intentToRetain: Boolean? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ConstraintField

        if (id != other.id) return false
        if (purpose != other.purpose) return false
        if (predicate != other.predicate) return false
        if (!path.contentEquals(other.path)) return false
        if (filter != other.filter) return false
        return intentToRetain == other.intentToRetain
    }

    override fun hashCode(): Int {
        var result = id?.hashCode() ?: 0
        result = 31 * result + (purpose?.hashCode() ?: 0)
        result = 31 * result + (predicate?.hashCode() ?: 0)
        result = 31 * result + path.contentHashCode()
        result = 31 * result + (filter?.hashCode() ?: 0)
        result = 31 * result + (intentToRetain?.hashCode() ?: 0)
        return result
    }
}