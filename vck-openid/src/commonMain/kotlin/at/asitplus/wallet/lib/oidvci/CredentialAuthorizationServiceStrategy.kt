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
    /** Source of user data. */
    private val dataProvider: OAuth2DataProvider,
    /** List of supported schemes. */
    credentialSchemes: Set<ConstantIndex.CredentialScheme>,
) : AuthorizationServiceStrategy {

    private val supportedCredentialSchemes = credentialSchemes
        .flatMap { it.toSupportedCredentialFormat().entries }
        .associate { it.key to it.value }

    override fun validScopes(): String = supportedCredentialSchemes.map { it.value.scope }.joinToString(" ")

    override fun allCredentialIdentifier(): Collection<String> = supportedCredentialSchemes.map { it.key }

    override fun validAuthorizationDetails(): Collection<OpenIdAuthorizationDetails> =
        supportedCredentialSchemes.entries.map {
            OpenIdAuthorizationDetails(credentialConfigurationId = it.key)
        }

    override suspend fun loadUserInfo(request: AuthenticationRequestParameters, code: String) =
        dataProvider.loadUserInfo(request, code)

    override fun filterScope(scope: String): String? = scope.trim().split(" ")
        .mapNotNull { scope ->
            if (supportedCredentialSchemes.values.find { it.scope == scope } != null) scope
            else null
        }
        .joinToString(" ")

    override fun filterAuthorizationDetails(authorizationDetails: Collection<AuthorizationDetails>) =
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

/**
 * Returns `true` if the [other] authorization detail is semantically the same,
 * i.e. it has either the same [OpenIdAuthorizationDetails.credentialConfigurationId]
 * or the same [OpenIdAuthorizationDetails.format] plus format-specific properties.
 */
fun OpenIdAuthorizationDetails.matches(other: OpenIdAuthorizationDetails): Boolean = when {
    credentialConfigurationId != null -> other.credentialConfigurationId == credentialConfigurationId
    format != null -> other.format == format
            && other.docType == docType
            && other.sdJwtVcType == sdJwtVcType
            && other.credentialDefinition == credentialDefinition

    else -> false
}