package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class Constraint(
    @SerialName("fields")
    val fields: Array<ConstraintField>? = null,
    @SerialName("limit_disclosure")
    val limitDisclosure: RequirementEnum? = null,
    @SerialName("statuses")
    val statuses: ConstraintStatusHolder? = null,
    @SerialName("subject_is_issuer")
    val subjectIsIssuer: RequirementEnum? = null,
    @SerialName("is_holder")
    val isHolder: Array<ConstraintHolder>? = null,
    @SerialName("same_subject")
    val sameSubject: Array<ConstraintHolder>? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Constraint

        if (fields != null) {
            if (other.fields == null) return false
            if (!fields.contentEquals(other.fields)) return false
        } else if (other.fields != null) return false
        if (limitDisclosure != other.limitDisclosure) return false
        if (statuses != other.statuses) return false
        if (subjectIsIssuer != other.subjectIsIssuer) return false
        if (isHolder != null) {
            if (other.isHolder == null) return false
            if (!isHolder.contentEquals(other.isHolder)) return false
        } else if (other.isHolder != null) return false
        if (sameSubject != null) {
            if (other.sameSubject == null) return false
            if (!sameSubject.contentEquals(other.sameSubject)) return false
        } else if (other.sameSubject != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = fields?.contentHashCode() ?: 0
        result = 31 * result + (limitDisclosure?.hashCode() ?: 0)
        result = 31 * result + (statuses?.hashCode() ?: 0)
        result = 31 * result + (subjectIsIssuer?.hashCode() ?: 0)
        result = 31 * result + (isHolder?.contentHashCode() ?: 0)
        result = 31 * result + (sameSubject?.contentHashCode() ?: 0)
        return result
    }
}