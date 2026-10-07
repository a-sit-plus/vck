package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TrustedEntityService(
    /** Current information identifying and describing the recognized service (TS 119 602, 6.4.3; 6.6). */
    @SerialName(SerialNames.SERVICE_INFORMATION)
    val serviceInformation: ServiceInformation,
    /** Previous status entries recorded for the service (TS 119 602, 6.4.4). */
    @SerialName(SerialNames.SERVICE_HISTORY)
    val serviceHistory: ServiceHistory? = null,
) {
    object SerialNames {
        /** Wire member name `ServiceInformation`. */
        const val SERVICE_INFORMATION = "ServiceInformation"
        /** Wire member name `ServiceHistory`. */
        const val SERVICE_HISTORY = "ServiceHistory"
    }
}