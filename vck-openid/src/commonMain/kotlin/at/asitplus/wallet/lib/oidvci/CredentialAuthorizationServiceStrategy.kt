package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.wallet.lib.oauth2.AuthorizationServiceStrategy

/**
 * Provide authentication and authorization for credential issuance.
 */
class CredentialAuthorizationServiceStrategy(
    /**
     * Source of user data.
     */
    private val dataProvider: OAuth2DataProvider,
    /**
     * Holds a list of supported credential schemes, to be transformed into matching data classes.
     */
    private val credentialSchemes: CredentialSchemeAdapter,
) : AuthorizationServiceStrategy {

    override suspend fun loadUserInfo(request: AuthenticationRequestParameters, code: String) =
        dataProvider.loadUserInfo(request, code)

    override fun filterAuthorizationDetails(authorizationDetails: Set<AuthorizationDetails>) =
        authorizationDetails
            .filterIsInstance<OpenIdAuthorizationDetails>()
            .filter { credentialSchemes.supportsAuthorization(it) }
            .map {
                if (it.credentialConfigurationId != null) {
                    it.copy(credentialIdentifiers = credentialSchemes.getCredentialDatasets(it.credentialConfigurationId!!))
                } else {
                    it
                }
            }
            .toSet()
}