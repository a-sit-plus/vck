package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CredentialOfferGrantsPreAuthCode
import at.asitplus.openid.OidcUserInfoExtended

/**
 * Extracted information from [at.asitplus.openid.AuthenticationRequestParameters],
 * to store what the client has initially requested (which [scope] and/or [authnDetails]),
 * and which [userInfo] is associated with that request.
 */
data class ClientAuthRequest(
    val issuedCode: String,
    val userInfo: OidcUserInfoExtended,
    val scope: String? = null,
    /** Validated [AuthorizationDetails] */
    val authnDetails: Collection<AuthorizationDetails>? = null,
    val codeChallenge: String? = null,
    /** Client information, which may be authenticated from PAR or self-stated */
    val clientBinding: ClientBinding? = null,
    /**
     * Credential configuration IDs of the credential offer this request belongs to, if any. Requested scopes and
     * authorization details must stay within them, i.e. an offer restricts what the client can obtain.
     */
    val configurationIds: Set<String>? = null,
    /**
     * OID4VCI transaction code the client has to present in the token request, if the offer demanded one.
     * Transmitted to the user out-of-band, see [CredentialOfferGrantsPreAuthCode.transactionCode].
     */
    val transactionCode: String? = null,
)
