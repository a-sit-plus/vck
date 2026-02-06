package at.asitplus.dcapi.issuance

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DigitalCredentialOfferReturnData(
    @SerialName("status")
    val status: String,
) {
    companion object {
        // Currently, only offer_accepted is defined in the corresponding pull request
        // https://github.com/openid/OpenID4VCI/blob/leecam-410-dcapi/openid-4-verifiable-credential-issuance-1_0.md
        // Will probably be refined before it hits a final specification
        const val STATUS_OFFER_ACCEPTED = "offer_accepted"
    }
}
