package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfoExtended

/**
 * Strategy to implement authentication and authorization in [SimpleAuthorizationService].
 */
interface AuthorizationServiceStrategy {

    suspend fun loadUserInfo(request: AuthenticationRequestParameters, code: String): OidcUserInfoExtended?

    fun filterAuthorizationDetails(authorizationDetails: Set<AuthorizationDetails>): Set<AuthorizationDetails>


}
