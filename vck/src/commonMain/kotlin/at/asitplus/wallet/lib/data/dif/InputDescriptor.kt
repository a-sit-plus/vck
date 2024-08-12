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
    val schema: Collection<SchemaReference>,
    @SerialName("constraints")
    val constraints: Constraint? = null,
) {
    constructor(name: String, schema: SchemaReference, constraints: Constraint? = null) : this(
        id = uuid4().toString(),
        name = name,
        schema = listOf(schema),
        constraints = constraints,
    )
}