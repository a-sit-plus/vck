package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class ConstraintHolder(
    @SerialName("field_id")
    val fieldIds: Array<String>,
    @SerialName("directive")
    val directive: RequirementEnum,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ConstraintHolder

        if (!fieldIds.contentEquals(other.fieldIds)) return false
        if (directive != other.directive) return false

        return true
    }

    override fun hashCode(): Int {
        var result = fieldIds.contentHashCode()
        result = 31 * result + directive.hashCode()
        return result
    }
}