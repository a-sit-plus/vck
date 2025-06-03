package at.asitplus.wallet.lib.rqes.helper

import CscAuthorizationDetails
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.wallet.lib.oauth2.AuthorizationServiceStrategy
import at.asitplus.wallet.lib.oauth2.ClientAuthRequest
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import io.github.aakira.napier.Napier

/**
 * Extends [CredentialAuthorizationServiceStrategy] by allowing [CscAuthorizationDetails].
 */
class RqesAuthorizationServiceStrategy(
    private val authorizationServiceStrategy: CredentialAuthorizationServiceStrategy
) : AuthorizationServiceStrategy by authorizationServiceStrategy {

    //We do not need to filter CscAuthDetails
    override fun filterAuthorizationDetails(authorizationDetails: Collection<AuthorizationDetails>): Set<AuthorizationDetails> =
        seperateAuthDetails(authorizationDetails).let { (openIdAuthDetails, cscAuthDetails) ->
            authorizationServiceStrategy.filterAuthorizationDetails(openIdAuthDetails) + cscAuthDetails
        }

    override fun matchAuthorizationDetails(
        clientRequest: ClientAuthRequest,
        filterAuthorizationDetails: Set<AuthorizationDetails>
    ) = seperateAuthDetails(filterAuthorizationDetails).let { (openIdAuthDetails, cscAuthDetails) ->
        authorizationServiceStrategy.matchAuthorizationDetails(clientRequest, openIdAuthDetails.toSet())
        cscAuthDetails.forEach { filter ->
            if (clientRequest.authnDetails!!.all { filter != it })
                throw InvalidRequest("Authorization details not from auth code: $filter")
        }
    }

    private fun seperateAuthDetails(authDetails: Collection<AuthorizationDetails>): Pair<Collection<OpenIdAuthorizationDetails>, Collection<CscAuthorizationDetails>> =
        (authDetails.filterIsInstance<OpenIdAuthorizationDetails>() to authDetails.filterIsInstance<CscAuthorizationDetails>()).also { (openIdAuth, cscAuth) ->
            if (openIdAuth.size + cscAuth.size != authDetails.size) Napier.w { "Not all authorization detail entries could be classified (they will be ignored!)" }
        }
}