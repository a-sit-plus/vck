package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TrustedEntity(
    /** Identity and contact information of the trusted entity (TS 119 602, 6.4.1; 6.5). */
    @SerialName(SerialNames.TRUSTED_ENTITY_INFORMATION)
    val trustedEntityInformation: TrustedEntityInformation,
    /** Services of the trusted entity recognized under the scheme (TS 119 602, 6.4.2). */
    @SerialName(SerialNames.TRUSTED_ENTITY_SERVICES)
    val trustedEntityServices: TrustedEntityServices,
) {
    object SerialNames {
        /** Wire member name `TrustedEntityInformation`. */
        const val TRUSTED_ENTITY_INFORMATION = "TrustedEntityInformation"
        /** Wire member name `TrustedEntityServices`. */
        const val TRUSTED_ENTITY_SERVICES = "TrustedEntityServices"
    }
}