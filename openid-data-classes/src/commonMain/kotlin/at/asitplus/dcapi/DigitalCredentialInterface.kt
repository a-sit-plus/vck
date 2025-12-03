package at.asitplus.dcapi

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DigitalCredentialInterface(
    /** `org-iso-mdoc`. */
    @SerialName("protocol")
    val protocol: ExchangeProtocolIdentifier,
    @SerialName("data")
    val data: DCAPIResponse,
)