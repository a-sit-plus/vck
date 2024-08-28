package at.asitplus.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class ConstraintStatusHolder(
    @SerialName("active")
    val active: ConstraintStatus? = null,
    @SerialName("suspended")
    val suspended: ConstraintStatus? = null,
    @SerialName("revoked")
    val revoked: ConstraintStatus? = null,
)