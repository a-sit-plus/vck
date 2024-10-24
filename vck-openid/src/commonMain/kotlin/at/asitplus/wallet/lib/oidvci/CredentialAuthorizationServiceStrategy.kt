package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.wallet.lib.data.ConstantIndex
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
     * List of supported schemes.
     */
    credentialSchemes: Set<ConstantIndex.CredentialScheme>,
) : AuthorizationServiceStrategy {

    private val supportedCredentialSchemes = credentialSchemes
        .flatMap { it.toSupportedCredentialFormat().entries }
        .associate { it.key to it.value }

    override suspend fun loadUserInfo(request: AuthenticationRequestParameters, code: String) =
        dataProvider.loadUserInfo(request, code)

    override fun filterAuthorizationDetails(authorizationDetails: Set<AuthorizationDetails>) =
        authorizationDetails
            .filterIsInstance<OpenIdAuthorizationDetails>()
            .filter { authnDetails ->
                authnDetails.credentialConfigurationId?.let {
                    supportedCredentialSchemes.containsKey(it)
                } ?: authnDetails.format?.let {
                    supportedCredentialSchemes.values.any {
                        it.format == authnDetails.format &&
                                it.docType == authnDetails.docType &&
                                it.sdJwtVcType == authnDetails.sdJwtVcType &&
                                it.credentialDefinition == authnDetails.credentialDefinition
                    }
                } ?: false
            }.toSet()
}