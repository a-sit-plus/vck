package at.asitplus.dif

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.catching
import com.benasher44.uuid.uuid4
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class PresentationDefinition(
    @SerialName("id")
    val id: String? = null,
    @SerialName("name")
    val name: String? = null,
    @SerialName("purpose")
    val purpose: String? = null,
    @SerialName("input_descriptors")
    val inputDescriptors: Collection<InputDescriptor>,
    @SerialName("submission_requirements")
    val submissionRequirements: Collection<SubmissionRequirement>? = null,
) {
    constructor(inputDescriptors: Collection<InputDescriptor>) : this(
        id = uuid4().toString(),
        inputDescriptors = inputDescriptors,
    )

    constructor(inputDescriptor: InputDescriptor) : this(
        id = uuid4().toString(),
        inputDescriptors = listOf(inputDescriptor),
    )

    fun serialize() = ddcJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = catching {
            ddcJsonSerializer.decodeFromString<PresentationDefinition>(it)
        }
    }
}

