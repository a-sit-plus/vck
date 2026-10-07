package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class ServiceHistoryInstance(
    /** Name under which the service was provided during this historical status (TS 119 602, 6.7; 6.6.2). */
    @SerialName(SerialNames.SERVICE_NAME)
    val serviceName: ServiceName,
    /** Digital identifiers applicable during this historical status (TS 119 602, 6.7). */
    @SerialName(SerialNames.SERVICE_DIGITAL_IDENTITY)
    val serviceDigitalIdentity: ServiceDigitalIdentity,
    /** URI identifying the previous status of the service (TS 119 602, 6.7; 6.6.4). */
    @SerialName(SerialNames.SERVICE_STATUS)
    val serviceStatus: ServiceStatus,
    /** UTC date and time at which this previous status became effective (TS 119 602, 6.7; 6.6.5). */
    @SerialName(SerialNames.STATUS_STARTING_TIME)
    @Serializable(with = EtsiInstantSerializer::class)
    val statusStartingTime: Instant,
    /** URI identifying the service type during this historical status (TS 119 602, 6.7; 6.6.1). */
    @SerialName(SerialNames.SERVICE_TYPE_IDENTIFIER)
    val serviceTypeIdentifier: ServiceTypeIdentifier? = null,
    /** Additional service-specific information for this historical status (TS 119 602, 6.7; 6.6.9). */
    @SerialName(SerialNames.SERVICE_INFORMATION_EXTENSIONS)
    val serviceInformationExtensions: ServiceInformationExtensions? = null,
) {
    object SerialNames {
        /** Wire member name `ServiceName`. */
        const val SERVICE_NAME = "ServiceName"
        /** Wire member name `ServiceDigitalIdentity`. */
        const val SERVICE_DIGITAL_IDENTITY = "ServiceDigitalIdentity"
        /** Wire member name `ServiceStatus`. */
        const val SERVICE_STATUS = "ServiceStatus"
        /** Wire member name `StatusStartingTime`. */
        const val STATUS_STARTING_TIME = "StatusStartingTime"
        /** Wire member name `ServiceTypeIdentifier`. */
        const val SERVICE_TYPE_IDENTIFIER = "ServiceTypeIdentifier"
        /** Wire member name `ServiceInformationExtensions`. */
        const val SERVICE_INFORMATION_EXTENSIONS = "ServiceInformationExtensions"
    }
}