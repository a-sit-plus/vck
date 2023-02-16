package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class ConstraintNotFilter(
    @SerialName("const")
    val const: String? = null,
    @SerialName("enum")
    val enum: Array<String>? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ConstraintNotFilter

        if (const != other.const) return false
        if (enum != null) {
            if (other.enum == null) return false
            if (!enum.contentEquals(other.enum)) return false
        } else if (other.enum != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = const?.hashCode() ?: 0
        result = 31 * result + (enum?.contentHashCode() ?: 0)
        return result
    }
}