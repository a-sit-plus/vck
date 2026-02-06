package at.asitplus.dcapi.issuance

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DigitalCredentialOfferReturn(
    @SerialName("protocol")
    val protocol: IssuanceProtocolIdentifier,
    @SerialName("data")
    val data: DigitalCredentialOfferReturnData,
) {
    companion object {
        fun success(
            protocol: IssuanceProtocolIdentifier = IssuanceProtocolIdentifier.OPENID4VCI_V1,
            status: String = DigitalCredentialOfferReturnData.STATUS_OFFER_ACCEPTED,
        ) = DigitalCredentialOfferReturn(
            protocol = protocol,
            data = DigitalCredentialOfferReturnData(status = status)
        )

        fun error(
            protocol: IssuanceProtocolIdentifier = IssuanceProtocolIdentifier.OPENID4VCI_V1,
            status: String,
        ) = DigitalCredentialOfferReturn(
            protocol = protocol,
            data = DigitalCredentialOfferReturnData(status = status)
        )

    }
}
