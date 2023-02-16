package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class ConstraintFilter(
    @SerialName("type")
    val type: String,
    @SerialName("format")
    val format: String? = null,
    @SerialName("const")
    val const: String? = null,
    @SerialName("pattern")
    val pattern: String? = null,
    @SerialName("exclusiveMinimum")
    val exclusiveMinimum: Int? = null,
    @SerialName("exclusiveMaximum")
    val exclusiveMaximum: Int? = null,
    @SerialName("minimum")
    val minimum: Int? = null,
    @SerialName("maximum")
    val maximum: Int? = null,
    @SerialName("minLength")
    val minLength: Int? = null,
    @SerialName("maxLength")
    val maxLength: Int? = null,
    @SerialName("enum")
    val enum: Array<String>? = null,
    @SerialName("not")
    val not: ConstraintNotFilter? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ConstraintFilter

        if (type != other.type) return false
        if (format != other.format) return false
        if (const != other.const) return false
        if (pattern != other.pattern) return false
        if (exclusiveMinimum != other.exclusiveMinimum) return false
        if (exclusiveMaximum != other.exclusiveMaximum) return false
        if (minimum != other.minimum) return false
        if (maximum != other.maximum) return false
        if (minLength != other.minLength) return false
        if (maxLength != other.maxLength) return false
        if (enum != null) {
            if (other.enum == null) return false
            if (!enum.contentEquals(other.enum)) return false
        } else if (other.enum != null) return false
        if (not != other.not) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + (format?.hashCode() ?: 0)
        result = 31 * result + (const?.hashCode() ?: 0)
        result = 31 * result + (pattern?.hashCode() ?: 0)
        result = 31 * result + (exclusiveMinimum ?: 0)
        result = 31 * result + (exclusiveMaximum ?: 0)
        result = 31 * result + (minimum ?: 0)
        result = 31 * result + (maximum ?: 0)
        result = 31 * result + (minLength ?: 0)
        result = 31 * result + (maxLength ?: 0)
        result = 31 * result + (enum?.contentHashCode() ?: 0)
        result = 31 * result + (not?.hashCode() ?: 0)
        return result
    }
}

