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

    override fun filterScope(scope: String): String? {
        if (supportedCredentialSchemes.containsKey(scope)) {
            return scope
        } else {
            return null
        }
    }

    override fun filterAuthorizationDetails(authorizationDetails: Set<AuthorizationDetails>) =
        authorizationDetails
            .filterIsInstance<OpenIdAuthorizationDetails>()
            .mapNotNull {
                when {
                    it.credentialConfigurationId != null -> it.filterCredentialConfigurationId()
                    it.format != null -> it.filterFormat()
                    else -> null
                }
            }
            .toSet()

    private fun OpenIdAuthorizationDetails.filterFormat(): OpenIdAuthorizationDetails? =
        supportedCredentialSchemes.entries.firstOrNull {
            it.value.format == format &&
                    it.value.docType == docType &&
                    it.value.sdJwtVcType == sdJwtVcType &&
                    it.value.credentialDefinition == credentialDefinition
        }?.let { matchingCredential ->
            copy(credentialIdentifiers = setOf(matchingCredential.key))
        }

    private fun OpenIdAuthorizationDetails.filterCredentialConfigurationId(): OpenIdAuthorizationDetails? =
        if (supportedCredentialSchemes.containsKey(credentialConfigurationId)) {
            copy(credentialIdentifiers = setOf(credentialConfigurationId!!))
        } else {
            null
        }
}