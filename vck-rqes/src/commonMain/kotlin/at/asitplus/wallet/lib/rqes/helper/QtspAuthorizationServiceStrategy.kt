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

@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.wallet.lib.rqes.QtspAuthorizationServiceStrategy"))
class QtspAuthorizationServiceStrategy(
    private val authorizationServiceStrategy: CredentialAuthorizationServiceStrategy,
)