package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdAuthorizationDetails

/**
 * Strategy to implement authentication and authorization in [SimpleAuthorizationService].
 */
interface AuthorizationServiceStrategy {

    suspend fun loadUserInfo(request: AuthenticationRequestParameters, code: String): OidcUserInfoExtended?

    fun filterAuthorizationDetails(authorizationDetails: Set<AuthorizationDetails>): Set<OpenIdAuthorizationDetails>

    fun filterScope(scope: String): String?


}
