package at.asitplus.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class Constraint(
    @SerialName("fields")
    val fields: Set<ConstraintField>? = null,
    /** Per ISO 18013-7, this shall be set to [RequirementEnum.REQUIRED] */
    @SerialName("limit_disclosure")
    val limitDisclosure: RequirementEnum? = null,
    @SerialName("statuses")
    val statuses: ConstraintStatusHolder? = null,
    @SerialName("subject_is_issuer")
    val subjectIsIssuer: RequirementEnum? = null,
    @SerialName("is_holder")
    val isHolder: Set<ConstraintHolder>? = null,
    @SerialName("same_subject")
    val sameSubject: Set<ConstraintHolder>? = null,
)