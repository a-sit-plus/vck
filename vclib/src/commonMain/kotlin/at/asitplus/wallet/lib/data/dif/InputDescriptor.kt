package at.asitplus.wallet.lib.data.dif

import com.benasher44.uuid.uuid4
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class InputDescriptor(
    @SerialName("id")
    val id: String,
    @SerialName("group")
    val group: String? = null,
    @SerialName("name")
    val name: String? = null,
    @SerialName("purpose")
    val purpose: String? = null,
    @SerialName("format")
    val format: FormatHolder? = null,
    @SerialName("schema")
    val schema: Array<SchemaReference>,
    @SerialName("constraints")
    val constraints: Constraint? = null,
) {
    constructor(name: String, schema: SchemaReference, constraints: Constraint? = null) : this(
        id = uuid4().toString(),
        name = name,
        schema = arrayOf(schema),
        constraints = constraints,
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as InputDescriptor

        if (id != other.id) return false
        if (group != other.group) return false
        if (name != other.name) return false
        if (purpose != other.purpose) return false
        if (format != other.format) return false
        if (!schema.contentEquals(other.schema)) return false
        if (constraints != other.constraints) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + (group?.hashCode() ?: 0)
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + (purpose?.hashCode() ?: 0)
        result = 31 * result + (format?.hashCode() ?: 0)
        result = 31 * result + schema.contentHashCode()
        result = 31 * result + (constraints?.hashCode() ?: 0)
        return result
    }
}