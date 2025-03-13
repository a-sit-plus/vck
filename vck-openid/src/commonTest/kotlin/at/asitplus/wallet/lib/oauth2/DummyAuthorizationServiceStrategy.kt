package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdAuthorizationDetails

class DummyAuthorizationServiceStrategy(
    private val user: OidcUserInfoExtended,
    private val scope: String,
) : AuthorizationServiceStrategy {
    override suspend fun loadUserInfo(
        request: AuthenticationRequestParameters,
        code: String,
    ): OidcUserInfoExtended? = user

    override fun validScopes(): String = scope

    override fun validAuthorizationDetails(): Collection<OpenIdAuthorizationDetails> = listOf()

    override fun filterAuthorizationDetails(authorizationDetails: Collection<AuthorizationDetails>): Set<OpenIdAuthorizationDetails> =
        setOf()

    override fun filterScope(scope: String): String? = scope
    override fun allCredentialIdentifier(): Collection<String> = listOf()

}
