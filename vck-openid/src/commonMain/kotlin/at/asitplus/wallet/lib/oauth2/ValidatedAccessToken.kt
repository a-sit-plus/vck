package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.wallet.lib.oidvci.TokenInfo
import kotlinx.serialization.Serializable

/** Internal class representing issued tokens. */
@Serializable
data class ValidatedAccessToken(
    val token: String,
    val userInfoExtended: OidcUserInfoExtended? = null,
    val authorizationDetails: Set<AuthorizationDetails>? = null,
    val scope: String? = null,
) {
    fun toTokenInfo() = TokenInfo(
        token = token,
        authorizationDetails = authorizationDetails,
        scope = scope,
    )
}

