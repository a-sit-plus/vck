package at.asitplus.wallet.lib.rqes.helper

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.rqes.CscAuthorizationDetails
import at.asitplus.wallet.lib.oauth2.AuthorizationServiceStrategy
import at.asitplus.wallet.lib.oauth2.ClientAuthRequest
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidAuthorizationDetails

/**
 * Implements Authorization for QTSP as necessary for Potential UC5
 */
class QtspAuthorizationServiceStrategy(
    private val authorizationServiceStrategy: CredentialAuthorizationServiceStrategy,
) : AuthorizationServiceStrategy by authorizationServiceStrategy {

    /**
     * QTSP can be assumed to only know CSC-related authn details ([CscAuthorizationDetails]) and rejet all others
     */
    override fun validateAuthorizationDetails(
        authorizationDetails: Collection<AuthorizationDetails>,
    ): Set<AuthorizationDetails> = authorizationDetails.filterIsInstance<CscAuthorizationDetails>().toSet().apply {
        if (this.size != authorizationDetails.size)
            throw InvalidAuthorizationDetails("Request may only contain CSC specific authorization details")
    }

    /**
     * Reject if authorization details from [tokenRequest] do not match 1:1 the ones from [authRequest]
     */
    override fun matchAuthorizationDetails(
        authRequest: ClientAuthRequest,
        tokenRequest: TokenRequestParameters,
    ): Set<AuthorizationDetails> = tokenRequest.authorizationDetails.apply {
        val validAuthCscDetails = authRequest.authnDetails
            ?.let { validateAuthorizationDetails(it) }
            ?: emptySet()
        val validTokenCscDetails = tokenRequest.authorizationDetails
            ?.let { validateAuthorizationDetails(it) }
            ?: emptySet()
        //Matching irrespective of order
        if (!validAuthCscDetails.containsAll(validTokenCscDetails))
            throw InvalidAuthorizationDetails("Authorization details do not match")
        if (!validTokenCscDetails.containsAll(validAuthCscDetails))
            throw InvalidAuthorizationDetails("Authorization details do not match")
    } ?: emptySet()
}