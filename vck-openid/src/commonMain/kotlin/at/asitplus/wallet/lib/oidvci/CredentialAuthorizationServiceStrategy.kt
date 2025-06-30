package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oauth2.AuthorizationServiceStrategy
import at.asitplus.wallet.lib.oauth2.ClientAuthRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidAuthorizationDetails


/**
 * Provide authentication and authorization for credential issuance.
 */
class CredentialAuthorizationServiceStrategy(
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

    override fun filterScope(scope: String): String = scope.trim().split(" ")
        .mapNotNull { scope ->
            if (supportedCredentialSchemes.values.find { it.scope == scope } != null) scope
            else null
        }.joinToString(" ")

    override fun validateAuthorizationDetails(
        authorizationDetails: Collection<AuthorizationDetails>,
    ) = authorizationDetails.map { it.validateAndTransform() }.toSet().ifEmpty {
        throw InvalidAuthorizationDetails("Token request for credential must contain authorization details")
    }

    /**
     * For credential issuing authorization details need to be present and need to match at least semantically
     */
    override fun matchAuthorizationDetails(
        authRequest: ClientAuthRequest,
        tokenRequest: TokenRequestParameters,
    ) = tokenRequest.authorizationDetails.let {
        if (it.isNullOrEmpty())
            throw InvalidAuthorizationDetails("Token request for credential must contain authorization details")

        validateAuthorizationDetails(it).onEach { filter ->
            if (authRequest.authnDetails!!.all { authDetails -> !filter.matches(authDetails) })
                throw InvalidAuthorizationDetails("Authorization details not from auth code: $filter")
        }
    }

    private fun AuthorizationDetails.validateAndTransform() = when (this) {
        is OpenIdAuthorizationDetails -> when {
            credentialConfigurationId != null -> filterCredentialConfigurationId()
            format != null -> filterFormat()
            else -> null
        } ?: throw InvalidAuthorizationDetails("Not a valid OpenIdAuthorizationDetail: $this")

        else -> throw InvalidAuthorizationDetails("Wrong type for issuance: $this")
    }

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
fun OpenIdAuthorizationDetails.matches(other: AuthorizationDetails): Boolean = when {
    other !is OpenIdAuthorizationDetails -> false
    credentialConfigurationId != null -> other.credentialConfigurationId == credentialConfigurationId
    format != null -> other.format == format
            && other.docType == docType
            && other.sdJwtVcType == sdJwtVcType
            && other.credentialDefinition == credentialDefinition

    else -> false
}

