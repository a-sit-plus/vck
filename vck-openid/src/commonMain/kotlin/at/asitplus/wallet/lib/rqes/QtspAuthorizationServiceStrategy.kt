package at.asitplus.wallet.lib.rqes

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CscAuthorizationDetails
import at.asitplus.wallet.lib.oauth2.AuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidAuthorizationDetails

/**
 * Implements Authorization for QTSP as necessary for Potential UC5
 */
class QtspAuthorizationServiceStrategy(
    private val authorizationServiceStrategy: CredentialAuthorizationServiceStrategy,
) : AuthorizationServiceStrategy by authorizationServiceStrategy {

    /**
     * QTSP can be assumed to only know CSC-related authn details ([at.asitplus.openid.CscAuthorizationDetails]) and rejet all others
     */
    override fun validateAuthorizationDetails(
        authorizationDetails: Collection<AuthorizationDetails>,
    ) {
        authorizationDetails
            .filterIsInstance<CscAuthorizationDetails>()
            .toSet()
            .apply {
                if (this.size != authorizationDetails.size)
                    throw InvalidAuthorizationDetails("Request may only contain CSC specific authorization details")
            }
    }

    private fun validateAndThrowAuthorizationDetails(
        authorizationDetails: Collection<AuthorizationDetails>,
    ): Set<AuthorizationDetails> = authorizationDetails
        .filterIsInstance<CscAuthorizationDetails>()
        .toSet().apply {
            if (this.size != authorizationDetails.size)
                throw InvalidAuthorizationDetails("Request may only contain CSC specific authorization details")
        }

    /**
     * Reject if authorization details from [tokenRequestAuthnDetails] do not match 1:1 the ones from [authRequest]
     */
    @Throws(InvalidAuthorizationDetails::class)
    override fun matchAndFilterAuthorizationDetailsForTokenResponse(
        authnRequestAuthnDetails: Collection<AuthorizationDetails>?,
        tokenRequestAuthnDetails: Set<AuthorizationDetails>,
    ): Set<AuthorizationDetails> {
        val validAuthCscDetails = authnRequestAuthnDetails
            ?.let { validateAndThrowAuthorizationDetails(it) }
            ?: emptySet()
        val validTokenCscDetails = validateAndThrowAuthorizationDetails(tokenRequestAuthnDetails)
        // Matching irrespective of order
        if (!validAuthCscDetails.containsAll(validTokenCscDetails))
            throw InvalidAuthorizationDetails("Authorization details do not match")
        if (!validTokenCscDetails.containsAll(validAuthCscDetails))
            throw InvalidAuthorizationDetails("Authorization details do not match")
        return validTokenCscDetails
    }
}