package at.asitplus.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class ConstraintFilter(
    @SerialName("type")
    val type: String? = null,
    @SerialName("format")
    val format: String? = null,
    @SerialName("const")
    val const: JsonPrimitive? = null,
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
    val enum: Set<String>? = null,
    @SerialName("not")
    val not: ConstraintNotFilter? = null,
)