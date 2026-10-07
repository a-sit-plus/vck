package at.asitplus.etsi

import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class ServiceSupplyPoint(
    /** URI specifying where and how the service or a related service can be accessed (TS 119 612, 5.5.7). */
    @SerialName(SerialNames.URI_VALUE)
    val uriValue: Rfc3986UniformResourceIdentifier,
    /** URI identifying the type of service accessible at [uriValue] (TS 119 612, 5.5.7). */
    @SerialName(SerialNames.SERVICE_TYPE)
    val serviceType: String? = null
) {
    object SerialNames {
        /** Wire member name `uriValue`. */
        const val URI_VALUE = "uriValue"

        /** Wire member name `ServiceType`. */
        const val SERVICE_TYPE = "ServiceType"
    }
}

@Serializable
data class ServiceInformation(
    /** Localized names under which the trusted entity provides the service (TS 119 602, 6.6.2). */
    @SerialName(SerialNames.SERVICE_NAME)
    val serviceName: List<MultilingualCharacterString>,
    /** Digital identifiers identifying the service in the context of its type (TS 119 602, 6.6.3). */
    @SerialName(SerialNames.SERVICE_DIGITAL_IDENTITY)
    val serviceDigitalIdentity: ServiceDigitalIdentity,
    /** URI identifying the type of service (TS 119 602, 6.6.1). */
    @SerialName(SerialNames.SERVICE_TYPE_IDENTIFIER)
    val serviceTypeIdentifier: ServiceTypeIdentifier? = null,
    /** URI identifying the current status of the service (TS 119 602, 6.6.4). */
    @SerialName(SerialNames.SERVICE_STATUS)
    val serviceStatus: ServiceStatus? = null,
    /** UTC date and time at which the current approval status became effective (TS 119 602, 6.6.5). */
    @SerialName(SerialNames.STATUS_STARTING_TIME)
    @Serializable(with = EtsiInstantSerializer::class)
    val statusStartingTime: Instant? = null,
    /** Localized pointers to service information supplied by the scheme operator (TS 119 602, 6.6.6). */
    @SerialName(SerialNames.SCHEME_SERVICE_DEFINITION_URI)
    val schemeServiceDefinitionURI: List<MultilingualPointer>? = null,
    /** Access locations for this service or related services, optionally specifying their types (TS 119 602, 6.6.7). */
    @SerialName(SerialNames.SERVICE_SUPPLY_POINTS)
    val serviceSupplyPoints: List<ServiceSupplyPoint>? = null,
    /** Localized pointers to service information supplied by the trusted entity (TS 119 602, 6.6.8). */
    @SerialName(SerialNames.SERVICE_DEFINITION_URI)
    val serviceDefinitionURI: List<MultilingualPointer>? = null,
    /** Additional service-specific information interpreted under the scheme rules (TS 119 602, 6.6.9). */
    @SerialName(SerialNames.SERVICE_INFORMATION_EXTENSIONS)
    val serviceInformationExtensions: ServiceInformationExtensions? = null,
) {
    init {
        require(serviceName.isNotEmpty()) { "Expected non-empty serviceName when present." }
        require(schemeServiceDefinitionURI?.isNotEmpty() != false) { "Expected non-empty schemeServiceDefinitionURI when present." }
        require(serviceDefinitionURI?.isNotEmpty() != false) { "Expected non-empty serviceDefinitionURI when present." }
        serviceSupplyPoints?.let {
            require(it.isNotEmpty()) {
                "Expected a non-empty list of service supply points or null, but got an empty list instead."
            }
        }
    }

    object SerialNames {
        /** Wire member name `ServiceName`. */
        const val SERVICE_NAME = "ServiceName"

        /** Wire member name `ServiceDigitalIdentity`. */
        const val SERVICE_DIGITAL_IDENTITY = "ServiceDigitalIdentity"

        /** Wire member name `ServiceTypeIdentifier`. */
        const val SERVICE_TYPE_IDENTIFIER = "ServiceTypeIdentifier"

        /** Wire member name `ServiceStatus`. */
        const val SERVICE_STATUS = "ServiceStatus"

        /** Wire member name `StatusStartingTime`. */
        const val STATUS_STARTING_TIME = "StatusStartingTime"

        /** Wire member name `SchemeServiceDefinitionURI`. */
        const val SCHEME_SERVICE_DEFINITION_URI = "SchemeServiceDefinitionURI"

        /** Wire member name `ServiceSupplyPoints`. */
        const val SERVICE_SUPPLY_POINTS = "ServiceSupplyPoints"

        /** Wire member name `ServiceDefinitionURI`. */
        const val SERVICE_DEFINITION_URI = "ServiceDefinitionURI"

        /** Wire member name `ServiceInformationExtensions`. */
        const val SERVICE_INFORMATION_EXTENSIONS = "ServiceInformationExtensions"
    }
}