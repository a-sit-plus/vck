package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TEAddress(
    /** Postal contact addresses of the trusted entity in one or more languages (TS 119 602, 6.5.3.1). */
    @SerialName(SerialNames.TE_POSTAL_ADDRESS)
    val tePostalAddress: PostalAddresses,
    /** Email, website and optional telephone URIs of the trusted entity (TS 119 602, 6.5.3.2). */
    @SerialName(SerialNames.TE_ELECTRONIC_ADDRESS)
    val teElectronicAddress: TEElectronicAddress,
) {
    object SerialNames {
        /** Wire member name `TEPostalAddress`. */
        const val TE_POSTAL_ADDRESS = "TEPostalAddress"
        /** Wire member name `TEElectronicAddress`. */
        const val TE_ELECTRONIC_ADDRESS = "TEElectronicAddress"
    }
}