package at.asitplus.dcapi.request.verifier

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.openid.RequestParameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed class DigitalCredentialGetRequest {
    abstract val protocol: ExchangeProtocolIdentifier

    @Serializable
    data class Oid4Vp(
        /** `openid4vp-v<version>-<request-type>`, see [ExchangeProtocolIdentifier]. */
        @SerialName("protocol")
        override val protocol: ExchangeProtocolIdentifier,
        @SerialName("data")
        val request: RequestParameters,
    ) : DigitalCredentialGetRequest()

    @Serializable
    data class IsoMdoc(
        /** `org-iso-mdoc`. */
        @SerialName("protocol")
        override val protocol: ExchangeProtocolIdentifier,
        @SerialName("data")
        val request: IsoMdocRequest,
    ) : DigitalCredentialGetRequest()
}
