package at.asitplus.etsi

import at.asitplus.rfc.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class ServiceSupplyPoint(
    @SerialName(SerialNames.URI_VALUE)
    val uriValue: Rfc3986UniformResourceIdentifier,
    @SerialName(SerialNames.SERVICE_TYPE)
    val serviceType: String,
) {
    object SerialNames {
        const val URI_VALUE = "uriValue"
        const val SERVICE_TYPE = "ServiceType"
    }
}

@Serializable
data class ServiceInformation(
    @SerialName(SerialNames.SERVICE_NAME)
    val serviceName: List<MultilingualCharacterString>,
    @SerialName(SerialNames.SERVICE_DIGITAL_IDENTITY)
    val serviceDigitalIdentity: ServiceDigitalIdentity,
    @SerialName(SerialNames.SERVICE_TYPE_IDENTIFIER)
    val serviceTypeIdentifier: ServiceTypeIdentifier? = null,
    @SerialName(SerialNames.SERVICE_STATUS)
    val serviceStatus: ServiceStatus? = null,
    @SerialName(SerialNames.STATUS_STARTING_TIME)
    @Serializable(with = EtsiInstantSerializer::class)
    val statusStartingTime: Instant? = null,
    @SerialName(SerialNames.SCHEME_SERVICE_DEFINITION_URI)
    val schemeServiceDefinitionURI: List<MultilingualPointer>? = null,
    @SerialName(SerialNames.SERVICE_SUPPLY_POINTS)
    val serviceSupplyPoints: List<ServiceSupplyPoint>? = null,
    @SerialName(SerialNames.SERVICE_DEFINITION_URI)
    val serviceDefinitionURI: List<MultilingualPointer>? = null,
    @SerialName(SerialNames.SERVICE_INFORMATION_EXTENSIONS)
    val serviceInformationExtensions: ServiceInformationExtensions? = null,
) {
    init {
        serviceSupplyPoints?.let {
            require(it.isNotEmpty()) {
                "Expected a non-empty list of service supply points or null, but got an empty list instead."
            }
        }
    }

    object SerialNames {
        const val SERVICE_NAME = "ServiceName"
        const val SERVICE_DIGITAL_IDENTITY = "ServiceDigitalIdentity"
        const val SERVICE_TYPE_IDENTIFIER = "ServiceTypeIdentifier"
        const val SERVICE_STATUS = "ServiceStatus"
        const val STATUS_STARTING_TIME = "StatusStartingTime"
        const val SCHEME_SERVICE_DEFINITION_URI = "SchemeServiceDefinitionURI"
        const val SERVICE_SUPPLY_POINTS = "ServiceSupplyPoints"
        const val SERVICE_DEFINITION_URI = "ServiceDefinitionURI"
        const val SERVICE_INFORMATION_EXTENSIONS = "ServiceInformationExtensions"
    }
}