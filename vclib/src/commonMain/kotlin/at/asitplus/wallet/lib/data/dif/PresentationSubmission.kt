package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-submission)
 */
@Serializable
data class PresentationSubmission(
    @SerialName("id")
    val id: String,
    @SerialName("definition_id")
    val definitionId: String,
    @SerialName("descriptor_map")
    val descriptorMap: Collection<PresentationSubmissionDescriptor>? = null,
)