package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.oauth2.AuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidAuthorizationDetails
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract


/**
 * Provide authentication and authorization for credential issuance.
 */
class CredentialAuthorizationServiceStrategy(
    /** List of supported schemes. */
    private val credentialSchemes: Set<ConstantIndex.CredentialScheme>,
    /** Maps from/to strings in metadata from/to credential schemes. */
    private val mapper: CredentialSchemeMapper = DefaultCredentialSchemeMapper(),
) : AuthorizationServiceStrategy {

    private val supportedCredentialSchemes = credentialSchemes
        .flatMap { mapper.map(it).entries }
        .associate { it.key to it.value }

    override fun validScopes(): String = supportedCredentialSchemes.map { it.value.scope }.distinct().joinToString(" ")

    override fun allCredentialIdentifier(): Set<String> = supportedCredentialSchemes.keys

    override fun toCredentialConfigurationIds(
        credentials: Set<Pair<ConstantIndex.CredentialScheme, CredentialRepresentation>>,
    ): Set<String> = if (credentials.isEmpty()) {
        allCredentialIdentifier()
    } else {
        credentials.mapNotNull { (scheme, representation) ->
            if (credentialSchemes.contains(scheme)) {
                runCatching { mapper.toCredentialIdentifier(scheme, representation) }.getOrNull()
            } else null
        }.toSet()
    }

    override fun validateAuthorizationDetails(
        authorizationDetails: Collection<AuthorizationDetails>,
        configurationIds: Set<String>,
    ): Boolean = authorizationDetails.all { it.validate() && it.credentialConfigurationId in configurationIds }

    override fun validAuthorizationDetails(location: String): Collection<OpenIdAuthorizationDetails> =
        supportedCredentialSchemes.entries.map {
            OpenIdAuthorizationDetails(credentialConfigurationId = it.key, locations = setOf(location))
        }

    override fun validateScope(
        scope: String,
        configurationIds: Set<String>,
    ): Boolean = scope.trim().split(" ")
        .all { supportedCredentialSchemes.filter { it.key in configurationIds }.map { it.value.scope }.contains(it) }

    override fun filterScope(scope: String): String = scope.trim().split(" ")
        .mapNotNull { scope ->
            if (supportedCredentialSchemes.values.find { it.scope == scope } != null) scope
            else null
        }.joinToString(" ")

    @Throws(InvalidAuthorizationDetails::class)
    override fun validateAuthorizationDetails(
        authorizationDetails: Collection<AuthorizationDetails>,
    ) {
        authorizationDetails
            .filter { it.validate() }
            .ifEmpty {
                throw InvalidAuthorizationDetails("Invalid authorization details")
            }
    }

    /**
     * Filters the authorization details received in the authorization request to include in the token response.
     */
    override fun filterAuthorizationDetailsForTokenResponse(
        authorizationDetails: Collection<AuthorizationDetails>,
    ): Set<AuthorizationDetails> = authorizationDetails
        .filterIsInstance<OpenIdAuthorizationDetails>()
        .filter { it.validate() }
        .forTokenResponse()
        .toSet()

    /**
     * For credential issuing authorization details need to be present and need to match at least semantically
     * the ones from the authentication request.
     */
    @Throws(InvalidAuthorizationDetails::class)
    override fun matchAndFilterAuthorizationDetailsForTokenResponse(
        authnRequestAuthnDetails: Collection<AuthorizationDetails>?,
        tokenRequestAuthnDetails: Set<AuthorizationDetails>,
    ): Set<AuthorizationDetails> {
        if (tokenRequestAuthnDetails.isEmpty())
            throw InvalidAuthorizationDetails("AuthnDetails in token request are empty")
        if (authnRequestAuthnDetails == null)
            throw InvalidAuthorizationDetails("No AuthnDetails from authn request")
        val filtered = tokenRequestAuthnDetails
            .filterIsInstance<OpenIdAuthorizationDetails>()
            .filter { it.credentialConfigurationId != null }
        if (filtered.size != tokenRequestAuthnDetails.size)
            throw InvalidAuthorizationDetails("Invalid authn details: More than in authn request")
        if (!authnRequestAuthnDetails.containsAll(filtered))
            throw InvalidAuthorizationDetails("AuthnDetails from token request not matching those from authn request")
        return filtered
            .matchesAuthnRequest(authnRequestAuthnDetails)
            .forTokenResponse()
            .toSet().apply {
                if (isEmpty())
                    throw InvalidAuthorizationDetails("No matching AuthnDetails in token request")
            }
    }

    @OptIn(ExperimentalContracts::class)
    private fun AuthorizationDetails.validate(): Boolean {
        contract {
            returns(true) implies (this@validate is OpenIdAuthorizationDetails)
        }
        return when (this) {
            is OpenIdAuthorizationDetails -> when {
                credentialConfigurationId != null -> supportedCredentialSchemes.containsKey(credentialConfigurationId)
                else -> false
            }

            else -> false
        }
    }

}

private fun Collection<OpenIdAuthorizationDetails>.matchesAuthnRequest(
    authnDetailsFromAuthRequest: Collection<AuthorizationDetails>?,
) = filter { tokenAuthnDetail ->
    authnDetailsFromAuthRequest
        ?.filterIsInstance<OpenIdAuthorizationDetails>()
        ?.none { authnRequestAuthnDetail ->
            authnRequestAuthnDetail.credentialConfigurationId == tokenAuthnDetail.credentialConfigurationId
        } != true
}

private fun Collection<OpenIdAuthorizationDetails>.forTokenResponse() = map {
    it.copy(
        credentialIdentifiers = setOf(it.credentialConfigurationId!!),
    )
}

/**
 * Returns `true` if the [other] authorization detail is semantically the same,
 * i.e., it has the same [OpenIdAuthorizationDetails.credentialConfigurationId].
 */
fun OpenIdAuthorizationDetails.matches(other: AuthorizationDetails): Boolean = when {
    other !is OpenIdAuthorizationDetails -> false
    credentialConfigurationId != null -> other.credentialConfigurationId == credentialConfigurationId
    else -> false
}
