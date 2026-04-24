package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SchemeOperatorAddress(
    @SerialName(SerialNames.POSTAL_ADDRESSES)
    val postalAddresses: PostalAddresses,
    @SerialName(SerialNames.ELECTRONIC_ADDRESSES)
    val electronicAddress: ElectronicAddress,
) {
    object SerialNames {
        const val POSTAL_ADDRESSES = "SchemeOperatorPostalAddress"
        const val ELECTRONIC_ADDRESSES = "SchemeOperatorElectronicAddress"
    }
}