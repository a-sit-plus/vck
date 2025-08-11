package at.asitplus.wallet.lib.rqes.helper

import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oauth2.AuthorizationService
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.OAuth2AuthorizationServerAdapter

/**
 * Potential UC5:
 * Simple wrapper for [SimpleAuthorizationService] which uses [QtspAuthorizationServiceStrategy]
 */

@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.wallet.lib.rqes.SimpleQtspAuthorizationService"))
class SimpleQtspAuthorizationService private constructor(
    private val authorizationService: SimpleAuthorizationService,
)