package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.wallet.lib.oidvci.OAuth2Exception

/**
 * Strategy to implement authorization for credential requests (with `scope` or [OpenIdAuthorizationDetails])
 * in [SimpleAuthorizationService].
 */
interface AuthorizationServiceStrategy {

    /**
     * RFC9396. The AS MUST refuse to process any unknown authorization details type or authorization details not conforming to
     * the respective type definition. The AS MUST abort processing and respond with an error
     * invalid_authorization_details to the client if any of the following are true of the objects in the
     * authorization_details structure:
     *  + contains an unknown authorization details type value,
     *  + is an object of known type but containing unknown fields,
     *  + contains fields of the wrong type for the authorization details type,
     *  + contains fields with invalid values for the authorization details type
     *  + is missing required fields for the authorization details type.
     */
    @Throws(OAuth2Exception.InvalidAuthorizationDetails::class)
    fun validateAuthorizationDetails(authorizationDetails: Collection<AuthorizationDetails>): Set<AuthorizationDetails>

    /**
     * RFC9396. (Ch. 6 paraphrased) Check if `AuthorizationDetails` in `TokenRequestParameters` have at most the same scope or are
     * implied by `AuthorizationDetails` in `ClientAuthRequest`.
     *
     * For credential requests semantic matching is used.
     * @return AuthorizationDetails from tokenRequest
     */
    @Throws(OAuth2Exception.InvalidAuthorizationDetails::class)
    fun matchAuthorizationDetails(
        authRequest: ClientAuthRequest,
        tokenRequest: TokenRequestParameters
    ): Set<AuthorizationDetails>

    /** Filter the requested scope in the access token request to ones valid for credential issuance */
    fun filterScope(scope: String): String?

    /** Return all valid scopes for pre-authorized codes, that the client may use in token requests */
    fun validScopes(): String

    /** Return all valid authorization details for pre-authorized codes, that the client may use in token requests */
    fun validAuthorizationDetails(): Collection<AuthorizationDetails>

    /** Return all valid credential identifiers for all schemes. */
    fun allCredentialIdentifier(): Collection<String>
}
