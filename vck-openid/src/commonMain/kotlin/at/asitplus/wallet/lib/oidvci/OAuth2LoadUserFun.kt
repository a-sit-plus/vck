package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OidcUserInfoExtended

/**
 * Interface used in [at.asitplus.wallet.lib.oauth2.AuthorizationService] to actually load user data during the
 * OAuth 2.0 flow, after an authn request (see [AuthenticationRequestParameters]) has been validated.
 */
fun interface OAuth2LoadUserFun {
    suspend operator fun invoke(
        input: OAuth2LoadUserFunInput,
    ): KmmResult<OidcUserInfoExtended>
}

data class OAuth2LoadUserFunInput(
    val request: AuthenticationRequestParameters,
    val code: String,
)