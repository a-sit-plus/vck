package at.asitplus.dcapi.request.verifier

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactStringSerializer
import at.asitplus.signum.indispensable.josef.JwsGeneral
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

@Serializable
@JsonClassDiscriminator(DigitalCredentialGetRequest.SerialNames.PROTOCOL)
sealed class DigitalCredentialGetRequest {
    abstract val protocol: ExchangeProtocolIdentifier

    @Serializable
    @SerialName(SerialNames.ORG_ISO_MDOC)
    data class IsoMdoc(
        @SerialName(SerialNames.DATA)
        val data: IsoMdocRequest,
    ) : DigitalCredentialGetRequest() {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.IsoMdocAnnexC

        @Deprecated("Renamed", replaceWith = ReplaceWith("data"))
        val request: IsoMdocRequest get() = data
    }

    sealed interface OpenId4Vp {
        @Serializable
        data class SignedDataElement(
            @SerialName(SerialNames.REQUEST)
            @Serializable(with = JwsCompactStringSerializer::class)
            val request: JwsCompact
        )

        @Serializable
        data class MultiSignedDataElement(
            @SerialName(SerialNames.REQUEST)
            val request: JwsGeneral
        )
    }

    @Serializable
    @SerialName(SerialNames.OPENID4VP_V1_SIGNED)
    data class OpenId4VpSigned(
        @SerialName(SerialNames.DATA)
        val data: OpenId4Vp.SignedDataElement,
    ) : DigitalCredentialGetRequest(), OpenId4Vp {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Signed

        @Deprecated("Renamed", replaceWith = ReplaceWith("data"))
        val request: OpenId4Vp.SignedDataElement get() = data
    }

    @Serializable
    @SerialName(SerialNames.OPENID4VP_V1_MULTISIGNED)
    data class OpenId4VpMultiSigned(
        @SerialName(SerialNames.DATA)
        val data: OpenId4Vp.MultiSignedDataElement,
    ) : DigitalCredentialGetRequest(), OpenId4Vp {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Multisigned
    }

    @Serializable
    @SerialName(SerialNames.OPENID4VP_V1_UNSIGNED)
    data class OpenId4VpUnsigned(
        @SerialName(SerialNames.DATA)
        val data: AuthenticationRequestParameters,
    ) : DigitalCredentialGetRequest(), OpenId4Vp {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Unsigned

        @Deprecated("Renamed", replaceWith = ReplaceWith("data"))
        val request: AuthenticationRequestParameters get() = data

    }

    object SerialNames {
        const val DATA = "data"
        const val REQUEST = "request"
        const val PROTOCOL = "protocol"
        const val ORG_ISO_MDOC = ExchangeProtocolIdentifier.ORG_ISO_MDOC
        const val OPENID4VP_V1_UNSIGNED = ExchangeProtocolIdentifier.OPENID4VP_V1_UNSIGNED
        const val OPENID4VP_V1_SIGNED = ExchangeProtocolIdentifier.OPENID4VP_V1_SIGNED
        const val OPENID4VP_V1_MULTISIGNED = ExchangeProtocolIdentifier.OPENID4VP_V1_MULTISIGNED
    }
}
