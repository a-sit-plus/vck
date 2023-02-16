package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class FormatContainerJwt(
    @SerialName("alg")
    val algorithms: Array<String>,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as FormatContainerJwt

        if (!algorithms.contentEquals(other.algorithms)) return false

        return true
    }

    override fun hashCode(): Int {
        return algorithms.contentHashCode()
    }
}