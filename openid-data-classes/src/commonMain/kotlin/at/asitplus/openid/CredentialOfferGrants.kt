package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VCI: Object indicating to the Wallet the Grant Types the Credential Issuer's Authorization Server is prepared to
 * process for this Credential Offer. Every grant is represented by a name/value pair. The name is the Grant Type
 * identifier; the value is an object that contains parameters either determining the way the Wallet MUST use the
 * particular grant and/or parameters the Wallet MUST send with the respective request(s).
 */
@Serializable
data class CredentialOfferGrants(
    @SerialName("authorization_code")
    val authorizationCode: CredentialOfferGrantsAuthCode? = null,

    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    val preAuthorizedCode: CredentialOfferGrantsPreAuthCode? = null
)