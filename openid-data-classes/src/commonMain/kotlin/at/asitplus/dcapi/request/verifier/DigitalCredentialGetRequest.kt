package at.asitplus.dcapi.request.verifier

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.openid.RequestParameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

@Serializable
@JsonClassDiscriminator("protocol")
sealed class DigitalCredentialGetRequest {
    abstract val protocol : ExchangeProtocolIdentifier

    @Serializable
    @SerialName("org-iso-mdoc")
    data class IsoMdoc(
        @SerialName("data")
        val request: IsoMdocRequest,
    ) : DigitalCredentialGetRequest() {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.ISO_MDOC_ANNEX_C
    }

    sealed interface OpenId4Vp

    @Serializable
    @SerialName("openid4vp-v1-signed")
    data class OpenId4VpSigned(
        @SerialName("data")
        val request: RequestParameters,
    ) : DigitalCredentialGetRequest(), OpenId4Vp {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OPENID4VP_V1_SIGNED
    }

    @Serializable
    @SerialName("openid4vp-v1-unsigned")
    data class OpenId4VpUnsigned(
        @SerialName("data")
        val request: RequestParameters,
    ) : DigitalCredentialGetRequest(), OpenId4Vp {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OPENID4VP_V1_UNSIGNED
    }

}
