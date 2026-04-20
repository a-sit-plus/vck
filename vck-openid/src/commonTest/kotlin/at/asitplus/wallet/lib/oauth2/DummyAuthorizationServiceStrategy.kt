package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidAuthorizationDetails

class DummyAuthorizationServiceStrategy(
    private val scope: String,
) : AuthorizationServiceStrategy {

    override fun validScopes(): String = scope

    override fun validAuthorizationDetails(location: String): Collection<OpenIdAuthorizationDetails> = listOf()

    override fun validateAuthorizationDetails(
        authorizationDetails: Collection<AuthorizationDetails>,
        configurationIds: Set<String>
    ): Boolean = false

    @Throws(InvalidAuthorizationDetails::class)
    override fun validateAuthorizationDetails(
        authorizationDetails: Collection<AuthorizationDetails>,
    ) {
        throw InvalidAuthorizationDetails()
    }

    override fun filterAuthorizationDetailsForTokenResponse(
        authorizationDetails: Collection<AuthorizationDetails>
    ) = authorizationDetails.filterIsInstance<OpenIdAuthorizationDetails>().toSet()

    @Throws(InvalidAuthorizationDetails::class)
    override fun matchAndFilterAuthorizationDetailsForTokenResponse(
        authnRequestAuthnDetails: Collection<AuthorizationDetails>?,
        tokenRequestAuthnDetails: Set<AuthorizationDetails>,
    ) = throw InvalidAuthorizationDetails()

    override fun filterScope(scope: String): String = scope

    override fun validateScope(
        scope: String,
        configurationIds: Set<String>
    ): Boolean = scope == this.scope

    override fun allCredentialIdentifier(): Set<String> = setOf()

    override fun toCredentialConfigurationIds(
        credentials: Set<Pair<ConstantIndex.CredentialScheme, ConstantIndex.CredentialRepresentation>>
    ): Set<String> {
        require(credentials.isEmpty()) {
            "DummyAuthorizationServiceStrategy does not support credential configuration mapping"
        }
        return emptySet()
    }

}
