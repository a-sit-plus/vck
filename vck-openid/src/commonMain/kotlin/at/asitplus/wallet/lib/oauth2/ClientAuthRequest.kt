package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
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
    val authnDetails: Collection<AuthorizationDetails>? = null,
    val codeChallenge: String? = null,
)
