package at.asitplus.dif

import com.benasher44.uuid.uuid4
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v2.1.1](https://identity.foundation/presentation-exchange/spec/v2.1.1/#term:presentation-definition)
 */
@Serializable
data class DifInputDescriptor(
    @SerialName("id")
    override val id: String,
    @SerialName("group")
    val groups: Collection<String>? = null,
    @SerialName("name")
    override val name: String? = null,
    @SerialName("purpose")
    override val purpose: String? = null,
    @SerialName("format")
    override val format: FormatHolder? = null,
    @SerialName("constraints")
    override val constraints: Constraint? = null,
) : InputDescriptor {
    constructor(name: String, constraints: Constraint? = null) : this(
        id = uuid4().toString(),
        name = name,
        constraints = constraints,
    )

    constructor(constraints: Constraint? = null) : this(
        id = uuid4().toString(),
        constraints = constraints,
    )

    override val group: String?
        get() = groups?.firstOrNull()
}
