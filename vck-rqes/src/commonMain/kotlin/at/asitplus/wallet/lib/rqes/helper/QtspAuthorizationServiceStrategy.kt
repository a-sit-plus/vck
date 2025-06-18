package at.asitplus.wallet.lib.rqes.helper

import CscAuthorizationDetails
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.wallet.lib.oauth2.AuthorizationServiceStrategy
import at.asitplus.wallet.lib.oauth2.ClientAuthRequest
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.OAuth2Exception

/**
 * Implements Authorization for QTSP as necessary for Use case 5
 */
class QtspAuthorizationServiceStrategy(
    private val authorizationServiceStrategy: CredentialAuthorizationServiceStrategy
) : AuthorizationServiceStrategy by authorizationServiceStrategy {

    //QTSP can be assumed to only know CSC related [AuthorizationDetails] and rejects all others
    override fun validateAuthorizationDetails(authorizationDetails: Collection<AuthorizationDetails>): Set<AuthorizationDetails> =
        authorizationDetails.filterIsInstance<CscAuthorizationDetails>().toSet().apply {
            if (this.size != authorizationDetails.size)
                throw OAuth2Exception.InvalidAuthorizationDetails("Request may only contain CSC specific authorization details")
        }

    //Reject if Authorization Details do not match 1:1
    override fun matchAuthorizationDetails(
        authRequest: ClientAuthRequest,
        tokenRequest: TokenRequestParameters
    ): Set<AuthorizationDetails> =
        tokenRequest.authorizationDetails.apply {
            val authCscDetails = authRequest.authnDetails?.let { validateAuthorizationDetails(it) } ?: emptySet()
            val tokenCscDetails = tokenRequest.authorizationDetails?.let { validateAuthorizationDetails(it) } ?: emptySet()
            //Matching irrespective of order
            if (!authCscDetails.containsAll(tokenCscDetails))
                throw OAuth2Exception.InvalidAuthorizationDetails("Authorization details do not match")
            if (!tokenCscDetails.containsAll(authCscDetails))
                throw OAuth2Exception.InvalidAuthorizationDetails("Authorization details do not match")
        } ?: emptySet()
}