package at.asitplus.dcapi.issuance

import at.asitplus.openid.CredentialOffer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * The DigitalCredentialCreateRequest dictionary represents an issuance request.
 * It is used to specify an issuance protocol and some request data,
 * to communicate the issuance request between the issuer and the holder.
 */
@Serializable
data class DigitalCredentialCreateRequest(
    @SerialName("protocol")
    val protocol: IssuanceProtocolIdentifier,
    @SerialName("data")
    val data: CredentialOffer,
)
