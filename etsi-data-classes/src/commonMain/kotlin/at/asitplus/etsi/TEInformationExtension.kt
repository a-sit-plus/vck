package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TEInformationExtension(
    @SerialName(SerialNames.OTHER_ASSOCIATED_BODIES)
    val otherAssociatedBodies: List<AssociatedBody>? = null,
) {
    object SerialNames {
        const val OTHER_ASSOCIATED_BODIES = "OtherAssociatedBodies"
    }
}