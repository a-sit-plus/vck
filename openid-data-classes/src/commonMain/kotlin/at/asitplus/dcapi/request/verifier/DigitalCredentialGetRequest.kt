package at.asitplus.dcapi.request.verifier

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import at.asitplus.openid.RequestParameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed class DigitalCredentialGetRequest {
    abstract val protocol: ExchangeProtocolIdentifier

    // TODO remove this?
    @Serializable
    data class SignedDigitalCredentialGetRequest(
        /** `org-iso-mdoc` or `openid4vp-v<version>-<request-type>`, see [ExchangeProtocolIdentifier]. */
        @SerialName("protocol")
        override val protocol: ExchangeProtocolIdentifier,
        @SerialName("data")
        val data: String,
    ) : DigitalCredentialGetRequest()

    @Serializable
    data class UnsignedDigitalCredentialGetRequest(
        /** `org-iso-mdoc` or `openid4vp-v<version>-<request-type>`, see [ExchangeProtocolIdentifier]. */
        @SerialName("protocol")
        override val protocol: ExchangeProtocolIdentifier,
        @SerialName("data")
        val request: RequestParameters,
    ) : DigitalCredentialGetRequest()
}
