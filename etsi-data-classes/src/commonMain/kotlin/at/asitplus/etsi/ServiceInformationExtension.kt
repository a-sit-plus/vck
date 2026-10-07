package at.asitplus.etsi

import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonIgnoreUnknownKeys

@Serializable
@JsonIgnoreUnknownKeys
data class ServiceInformationExtension(
    /** URI uniquely and unambiguously identifying the service within the scheme (TS 119 602, 6.6.9.1). */
    @SerialName(SerialNames.SERVICE_UNIQUE_IDENTIFIER)
    val serviceUniqueIdentifier: Rfc3986UniformResourceIdentifier
) {
    object SerialNames {
        /** Wire member name `ServiceUniqueIdentifier`. */
        const val SERVICE_UNIQUE_IDENTIFIER = "ServiceUniqueIdentifier"
    }
}