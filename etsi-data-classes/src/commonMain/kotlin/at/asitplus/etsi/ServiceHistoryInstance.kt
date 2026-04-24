package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class ServiceHistoryInstance(
    @SerialName(SerialNames.SERVICE_NAME)
    val serviceName: ServiceName,
    @SerialName(SerialNames.SERVICE_DIGITAL_IDENTITY)
    val serviceDigitalIdentity: ServiceDigitalIdentity,
    @SerialName(SerialNames.SERVICE_STATUS)
    val serviceStatus: ServiceStatus,
    @SerialName(SerialNames.STATUS_STARTING_TIME)
    @Serializable(with = EtsiInstantSerializer::class)
    val statusStartingTime: Instant,
    @SerialName(SerialNames.SERVICE_TYPE_IDENTIFIER)
    val serviceTypeIdentifier: ServiceTypeIdentifier? = null,
    @SerialName(SerialNames.SERVICE_INFORMATION_EXTENSIONS)
    val serviceInformationExtensions: ServiceInformationExtensions? = null,
) {
    object SerialNames {
        const val SERVICE_NAME = "ServiceName"
        const val SERVICE_DIGITAL_IDENTITY = "ServiceDigitalIdentity"
        const val SERVICE_STATUS = "ServiceStatus"
        const val STATUS_STARTING_TIME = "StatusStartingTime"
        const val SERVICE_TYPE_IDENTIFIER = "ServiceTypeIdentifier"
        const val SERVICE_INFORMATION_EXTENSIONS = "ServiceInformationExtensions"
    }
}