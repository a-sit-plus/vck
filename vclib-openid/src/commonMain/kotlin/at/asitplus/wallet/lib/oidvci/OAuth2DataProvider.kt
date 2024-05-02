package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters

/**
 * Interface used in [SimpleAuthorizationService] to actually load user data, converting it into [OidcUserInfo].
 */
interface OAuth2DataProvider {
    /**
     * Load user information (i.e. authenticate the client) with data sent from [request].
     *
     * @param request May be null when using pre-authorized code flow (defined in OID4VCI).
     */
    suspend fun loadUserInfo(request: AuthenticationRequestParameters? = null): OidcUserInfoExtended
}