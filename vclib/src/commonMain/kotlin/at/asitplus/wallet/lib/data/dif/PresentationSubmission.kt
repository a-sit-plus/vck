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
    val descriptorMap: Array<PresentationSubmissionDescriptor>? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as PresentationSubmission

        if (id != other.id) return false
        if (definitionId != other.definitionId) return false
        if (descriptorMap != null) {
            if (other.descriptorMap == null) return false
            if (!descriptorMap.contentEquals(other.descriptorMap)) return false
        } else if (other.descriptorMap != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + definitionId.hashCode()
        result = 31 * result + (descriptorMap?.contentHashCode() ?: 0)
        return result
    }
}