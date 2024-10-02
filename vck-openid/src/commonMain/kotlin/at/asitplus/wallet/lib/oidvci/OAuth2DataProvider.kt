package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OidcUserInfoExtended

/**
 * Interface used in [CredentialAuthorizationServiceStrategy] to actually load user data when client requests
 * and authorization code.
 */
interface OAuth2DataProvider {
    /**
     * Load user information (i.e. authenticate the client) with data sent from [request].
     */
    suspend fun loadUserInfo(request: AuthenticationRequestParameters, code: String): OidcUserInfoExtended?
}