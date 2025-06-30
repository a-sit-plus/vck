package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.wallet.lib.oidvci.OAuth2DataProvider
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidAuthorizationDetails
import at.asitplus.wallet.lib.oidvci.matches

class DummyAuthorizationServiceStrategy(
    private val scope: String,
) : AuthorizationServiceStrategy {

    override fun validScopes(): String = scope

    override fun validAuthorizationDetails(): Collection<OpenIdAuthorizationDetails> = listOf()

    override fun validateAuthorizationDetails(
        authorizationDetails: Collection<AuthorizationDetails>,
    ): Set<AuthorizationDetails> = authorizationDetails.toSet().also {
        if (it.isEmpty())
            throw InvalidAuthorizationDetails("No valid authorization details in $authorizationDetails")
    }

    override fun matchAuthorizationDetails(
        authRequest: ClientAuthRequest,
        tokenRequest: TokenRequestParameters,
    ) = tokenRequest.authorizationDetails?.apply {
        val validatedAuthnDetails = tokenRequest.authorizationDetails
            ?.let { validateAuthorizationDetails(it) }
            ?: emptySet()
        validatedAuthnDetails.filterIsInstance<OpenIdAuthorizationDetails>().forEach { filter ->
            if (!filter.requestedFromCode(authRequest))
                throw InvalidAuthorizationDetails("Authorization details not from auth code: $filter")
        }
    } ?: emptySet()

    private fun OpenIdAuthorizationDetails.requestedFromCode(clientAuthnRequest: ClientAuthRequest): Boolean =
        clientAuthnRequest.authnDetails!!.filterIsInstance<OpenIdAuthorizationDetails>().any { matches(it) }

    override fun filterScope(scope: String): String = scope

    override fun allCredentialIdentifier(): Collection<String> = listOf()

}

class DummyDataProvider(private val user: OidcUserInfoExtended) : OAuth2DataProvider {
    override suspend fun loadUserInfo(
        request: AuthenticationRequestParameters,
        code: String,
    ): OidcUserInfoExtended? = user
}