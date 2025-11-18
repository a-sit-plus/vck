package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidAuthorizationDetails
import at.asitplus.wallet.lib.oidvci.matches

class DummyAuthorizationServiceStrategy(
    private val scope: String,
) : AuthorizationServiceStrategy {

    override fun validScopes(): String = scope

    override fun validAuthorizationDetails(location: String): Collection<OpenIdAuthorizationDetails> = listOf()

    @Throws(InvalidAuthorizationDetails::class)
    override fun validateAuthorizationDetails(
        authorizationDetails: Collection<AuthorizationDetails>,
    ) {
        authorizationDetails.toSet().also {
            if (it.isEmpty())
                throw InvalidAuthorizationDetails("No valid authorization details in $authorizationDetails")
        }
    }

    override fun filterAuthorizationDetailsForTokenResponse(
        authorizationDetails: Collection<AuthorizationDetails>
    ) = authorizationDetails.filterIsInstance<OpenIdAuthorizationDetails>().toSet()


    @Throws(InvalidAuthorizationDetails::class)
    override fun matchAndFilterAuthorizationDetailsForTokenResponse(
        authnRequestAuthnDetails: Collection<AuthorizationDetails>?,
        tokenRequestAuthnDetails: Set<AuthorizationDetails>,
    ) = tokenRequestAuthnDetails
        .filterIsInstance<OpenIdAuthorizationDetails>()
        .toSet()
        .apply {
            this.forEach { filter ->
                if (!filter.requestedFromAuthnRequest(authnRequestAuthnDetails))
                    throw InvalidAuthorizationDetails("Authorization details not from auth code: $filter")
            }
        }


    private fun OpenIdAuthorizationDetails.requestedFromAuthnRequest(
        details: Collection<AuthorizationDetails>?
    ): Boolean = details!!.filterIsInstance<OpenIdAuthorizationDetails>().any { matches(it) }

    override fun filterScope(scope: String): String = scope

    override fun allCredentialIdentifier(): Collection<String> = listOf()

}

