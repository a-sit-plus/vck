package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TEAddress(
    @SerialName(SerialNames.TE_POSTAL_ADDRESS)
    val tePostalAddress: PostalAddresses,
    @SerialName(SerialNames.TE_ELECTRONIC_ADDRESS)
    val teElectronicAddress: TEElectronicAddress,
) {
    object SerialNames {
        const val TE_POSTAL_ADDRESS = "TEPostalAddress"
        const val TE_ELECTRONIC_ADDRESS = "TEElectronicAddress"
    }
}