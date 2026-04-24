package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TrustedEntityService(
    @SerialName(SerialNames.SERVICE_INFORMATION)
    val serviceInformation: ServiceInformation,
    @SerialName(SerialNames.SERVICE_HISTORY)
    val serviceHistory: ServiceHistory? = null,
) {
    object SerialNames {
        const val SERVICE_INFORMATION = "ServiceInformation"
        const val SERVICE_HISTORY = "ServiceHistory"
    }
}