package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails

/**
 * Strategy to implement authorization for credential requests (with `scope` or [OpenIdAuthorizationDetails])
 * in [SimpleAuthorizationService].
 */
interface AuthorizationServiceStrategy {

    /** Filter requested authorization details in token requests */
    fun filterAuthorizationDetails(authorizationDetails: Collection<AuthorizationDetails>): Set<AuthorizationDetails>

    /** Semantically match filtered authorization details against request */
    fun matchAuthorizationDetails(
        clientRequest: ClientAuthRequest,
        filteredAuthorizationDetails: Set<AuthorizationDetails>
    ): Unit

    /** Filter the requested scope in the access token request to ones valid for credential issuance */
    fun filterScope(scope: String): String?

    /** Return all valid scopes for pre-authorized codes, that the client may use in token requests */
    fun validScopes(): String

    /** Return all valid authorization details for pre-authorized codes, that the client may use in token requests */
    fun validAuthorizationDetails(): Collection<AuthorizationDetails>

    /** Return all valid credential identifiers for all schemes. */
    fun allCredentialIdentifier(): Collection<String>
}
