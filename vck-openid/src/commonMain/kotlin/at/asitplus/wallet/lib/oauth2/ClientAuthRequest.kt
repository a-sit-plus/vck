package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfoExtended

data class ClientAuthRequest(
    val issuedCode: String,
    val userInfoExtended: OidcUserInfoExtended,
    val scope: String? = null,
    val authnDetails: Collection<AuthorizationDetails>? = null,
    val codeChallenge: String? = null,
)
