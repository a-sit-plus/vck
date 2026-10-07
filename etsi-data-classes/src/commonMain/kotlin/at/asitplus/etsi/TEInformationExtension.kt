package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TEInformationExtension(
    /**
     * Bodies associated with the trusted entity in a way relevant to the scheme and listed services (TS 119 602,
     * 6.5.5.1).
     */
    @SerialName(SerialNames.OTHER_ASSOCIATED_BODIES)
    val otherAssociatedBodies: List<AssociatedBody>? = null,
) {
    object SerialNames {
        /** Wire member name `OtherAssociatedBodies`. */
        const val OTHER_ASSOCIATED_BODIES = "OtherAssociatedBodies"
    }
}