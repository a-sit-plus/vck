package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TrustedEntity(
    @SerialName(SerialNames.TRUSTED_ENTITY_INFORMATION)
    val trustedEntityInformation: TrustedEntityInformation,
    @SerialName(SerialNames.TRUSTED_ENTITY_SERVICES)
    val trustedEntityServices: TrustedEntityServices,
) {
    object SerialNames {
        const val TRUSTED_ENTITY_INFORMATION = "TrustedEntityInformation"
        const val TRUSTED_ENTITY_SERVICES = "TrustedEntityServices"
    }
}