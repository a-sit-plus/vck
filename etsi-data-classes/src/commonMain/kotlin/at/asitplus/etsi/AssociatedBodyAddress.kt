package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AssociatedBodyAddress(
    @SerialName(SerialNames.ASSOCIATED_BODY_POSTAL_ADDRESS)
    val assosciatedBodyPostalAddress: PostalAddresses,
    @SerialName(SerialNames.ASSOCIATED_BODY_ELECTRONIC_ADDRESS)
    val assosciatedBodyElectronicAddress: ElectronicAddress,
) {
    object SerialNames {
        const val ASSOCIATED_BODY_POSTAL_ADDRESS = "AssociatedBodyPostalAddress"
        const val ASSOCIATED_BODY_ELECTRONIC_ADDRESS = "AssociatedBodyElectronicAddress"
    }
}