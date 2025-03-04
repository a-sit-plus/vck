package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdAuthorizationDetails

data class IssuedAccessToken(
    val token: String,
    val userInfoExtended: OidcUserInfoExtended,
    val scope: String? = null,
    val authorizationDetails: Set<OpenIdAuthorizationDetails>? = null,
) {
    constructor(
        token: String,
        userInfoExtended: OidcUserInfoExtended,
        scope: String,
    ) : this(
        token = token,
        userInfoExtended = userInfoExtended,
        scope = scope,
        authorizationDetails = null
    )

    constructor(
        token: String,
        userInfoExtended: OidcUserInfoExtended,
        authorizationDetails: Set<OpenIdAuthorizationDetails>,
    ) : this(
        token = token,
        userInfoExtended = userInfoExtended,
        scope = null,
        authorizationDetails = authorizationDetails
    )
}
