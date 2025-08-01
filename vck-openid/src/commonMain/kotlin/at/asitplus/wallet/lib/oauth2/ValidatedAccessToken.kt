package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdAuthorizationDetails

data class ValidatedAccessToken(
    val token: String,
    val userInfoExtended: OidcUserInfoExtended? = null,
    val authorizationDetails: Set<AuthorizationDetails>? = null,
    val scope: String? = null,
) {
    val validCredentialIdentifiers = authorizationDetails
        ?.filterIsInstance<OpenIdAuthorizationDetails>()
        ?.flatMap { it.credentialIdentifiers ?: setOf() }
        ?: setOf()
}