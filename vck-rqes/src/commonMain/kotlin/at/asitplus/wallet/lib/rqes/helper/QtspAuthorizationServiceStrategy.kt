package at.asitplus.wallet.lib.rqes.helper

import CscAuthorizationDetails
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.TokenRequestParameters
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


    //TODO wsl reject falls etwas anderes als CSC drin is
    override fun validateAuthorizationDetails(authorizationDetails: Collection<AuthorizationDetails>): Set<AuthorizationDetails> =
        separateAuthDetails(authorizationDetails).let { (openIdAuthDetails, cscAuthDetails) ->
            authorizationServiceStrategy.validateAuthorizationDetails(openIdAuthDetails) + cscAuthDetails
        }

    //TODO wsl reject wenn nicht 1:1 matched
    override fun matchAuthorizationDetails(
        authRequest: ClientAuthRequest,
        tokenRequest: TokenRequestParameters
    ) = separateAuthDetails(filteredAuthorizationDetails).let { (openIdAuthDetails, cscAuthDetails) ->
        authorizationServiceStrategy.matchAuthorizationDetails(clientRequest, openIdAuthDetails.toSet())
        cscAuthDetails.forEach { filter ->
            if (clientRequest.authnDetails!!.all { filter != it })
                throw InvalidRequest("Authorization details not from auth code: $filter")
        }
    }

    private fun separateAuthDetails(authDetails: Collection<AuthorizationDetails>): Pair<Collection<OpenIdAuthorizationDetails>, Collection<CscAuthorizationDetails>> =
        (authDetails.filterIsInstance<OpenIdAuthorizationDetails>() to authDetails.filterIsInstance<CscAuthorizationDetails>()).also { (openIdAuth, cscAuth) ->
            if (openIdAuth.size + cscAuth.size != authDetails.size) Napier.w { "Not all authorization detail entries could be classified (they will be ignored!)" }
        }
}