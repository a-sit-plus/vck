package at.asitplus.dcapi

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import at.asitplus.openid.AuthenticationResponseParameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DCAPIBrowserResponse(
    /** Format `openid4vp-v<version>-<request-type>`, see [ExchangeProtocolIdentifier]. */
    @SerialName("protocol")
    val protocol: ExchangeProtocolIdentifier,
    @SerialName("data")
    val data: AuthenticationResponseParameters,
    @SerialName("origin")
    val origin: String,
)