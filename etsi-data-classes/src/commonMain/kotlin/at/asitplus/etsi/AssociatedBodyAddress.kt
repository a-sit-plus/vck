package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AssociatedBodyAddress(
    /** Postal contact addresses of the associated body in one or more languages (TS 119 602, 6.5.5.1.4.1). */
    @SerialName(SerialNames.ASSOCIATED_BODY_POSTAL_ADDRESS)
    val assosciatedBodyPostalAddress: PostalAddresses,
    /** Email, website and optional telephone contact URIs of the associated body (TS 119 602, 6.5.5.1.4.2). */
    @SerialName(SerialNames.ASSOCIATED_BODY_ELECTRONIC_ADDRESS)
    val assosciatedBodyElectronicAddress: ElectronicAddress,
) {
    object SerialNames {
        /** Wire member name `AssociatedBodyPostalAddress`. */
        const val ASSOCIATED_BODY_POSTAL_ADDRESS = "AssociatedBodyPostalAddress"
        /** Wire member name `AssociatedBodyElectronicAddress`. */
        const val ASSOCIATED_BODY_ELECTRONIC_ADDRESS = "AssociatedBodyElectronicAddress"
    }
}