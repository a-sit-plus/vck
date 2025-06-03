package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.wallet.lib.oidvci.OAuth2DataProvider
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.matches

class DummyAuthorizationServiceStrategy(
    private val scope: String,
) : AuthorizationServiceStrategy {

    override fun validScopes(): String = scope

    override fun validAuthorizationDetails(): Collection<OpenIdAuthorizationDetails> = listOf()

    override fun filterAuthorizationDetails(authorizationDetails: Collection<AuthorizationDetails>): Set<AuthorizationDetails> =
        authorizationDetails.toSet().also { if (it.isEmpty()) throw InvalidRequest("No valid authorization details in $authorizationDetails") }

    override fun matchAuthorizationDetails(
        clientRequest: ClientAuthRequest,
        filterAuthorizationDetails: Set<AuthorizationDetails>
    ) = (filterAuthorizationDetails as? Set<OpenIdAuthorizationDetails>)?.forEach { filter ->
            if (!filter.requestedFromCode(clientRequest))
                throw InvalidRequest("Authorization details not from auth code: $filter")
        } ?: throw InvalidRequest("Request does not contain OAuth authorization details: $clientRequest")

    private fun OpenIdAuthorizationDetails.requestedFromCode(clientAuthRequest: ClientAuthRequest): Boolean =
        clientAuthRequest.authnDetails!!.filterIsInstance<OpenIdAuthorizationDetails>().any { matches(it) }

    override fun filterScope(scope: String): String = scope
    override fun allCredentialIdentifier(): Collection<String> = listOf()

}

class DummyDataProvider(private val user: OidcUserInfoExtended) : OAuth2DataProvider {
    override suspend fun loadUserInfo(
        request: AuthenticationRequestParameters,
        code: String,
    ): OidcUserInfoExtended? {
        return user
    }
}