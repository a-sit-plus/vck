package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OidcUserInfoExtended

/**
 * Interface used in [CredentialAuthorizationServiceStrategy] to actually load user data during the OAuth 2.0 flow,
 * after an authn request (see [AuthenticationRequestParameters]) has been validated.
 */
fun interface OAuth2DataProvider {
    /** [request] has been validated successfully, and this step loads the actual user data, if there is any. */
    suspend fun loadUserInfo(request: AuthenticationRequestParameters, code: String): OidcUserInfoExtended?
}