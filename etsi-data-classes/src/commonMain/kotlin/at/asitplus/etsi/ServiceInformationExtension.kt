package at.asitplus.etsi

import at.asitplus.rfc.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonIgnoreUnknownKeys

@Serializable
@JsonIgnoreUnknownKeys
data class ServiceInformationExtension(
    @SerialName(SerialNames.SERVICE_UNIQUE_IDENTIFIER)
    val serviceUniqueIdentifier: Rfc3986UniformResourceIdentifier
) {
    object SerialNames {
        const val SERVICE_UNIQUE_IDENTIFIER = "ServiceUniqueIdentifier"
    }
}