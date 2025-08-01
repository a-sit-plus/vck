package at.asitplus.dif

import com.benasher44.uuid.uuid4
import kotlinx.serialization.Contextual
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

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
    val inputDescriptors: Collection<@Contextual InputDescriptor>,
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
}

