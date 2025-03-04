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

    /** Filter requested authorization details in token requests to ones valued for credential issuance */
    fun filterAuthorizationDetails(authorizationDetails: Collection<AuthorizationDetails>): Set<OpenIdAuthorizationDetails>

    /** Filter the requested scope in the access token request to ones valid for credential issuance */
    fun filterScope(scope: String): String?

    /** Return all valid scopes for pre-authorized codes, that the client may use in token requests */
    fun validScopes(): String

    /** Return all valid authorization details for pre-authorized codes, that the client may use in token requests */
    fun validAuthorizationDetails(): Collection<OpenIdAuthorizationDetails>


}
