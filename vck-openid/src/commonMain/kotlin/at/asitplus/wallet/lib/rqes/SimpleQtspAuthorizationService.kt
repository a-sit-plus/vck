package at.asitplus.wallet.lib.rqes

import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oauth2.AuthorizationService
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.OAuth2AuthorizationServerAdapter

/**
 * Potential UC5:
 * Simple wrapper for [at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService] which uses [QtspAuthorizationServiceStrategy]
 */
class SimpleQtspAuthorizationService private constructor(
    private val authorizationService: SimpleAuthorizationService,
) : OAuth2AuthorizationServerAdapter by authorizationService, AuthorizationService by authorizationService {

    constructor(
        acceptedCredentials: Collection<ConstantIndex.CredentialScheme>,
    ) : this(
        authorizationService = SimpleAuthorizationService(
            strategy = QtspAuthorizationServiceStrategy(
                authorizationServiceStrategy = CredentialAuthorizationServiceStrategy(
                    acceptedCredentials.toSet()
                )
            )
        )
    )
}