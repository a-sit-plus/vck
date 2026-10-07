package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SchemeOperatorAddress(
    /** Localized postal addresses for enquiries and complaints to the scheme operator (TS 119 602, 6.3.5.1). */
    @SerialName(SerialNames.POSTAL_ADDRESSES)
    val postalAddresses: PostalAddresses,
    /** Email, website and optional telephone URIs for contacting the scheme operator (TS 119 602, 6.3.5.2). */
    @SerialName(SerialNames.ELECTRONIC_ADDRESSES)
    val electronicAddress: ElectronicAddress,
) {
    object SerialNames {
        /** Wire member name `SchemeOperatorPostalAddress`. */
        const val POSTAL_ADDRESSES = "SchemeOperatorPostalAddress"
        /** Wire member name `SchemeOperatorElectronicAddress`. */
        const val ELECTRONIC_ADDRESSES = "SchemeOperatorElectronicAddress"
    }
}