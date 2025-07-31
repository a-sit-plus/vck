package at.asitplus.wallet.lib.rqes.helper

import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oauth2.AuthorizationService
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.OAuth2AuthorizationServerAdapter
import at.asitplus.wallet.lib.oidvci.OAuth2DataProvider

/**
 * Potential UC5:
 * Simple wrapper for [SimpleAuthorizationService] which uses [QtspAuthorizationServiceStrategy]
 */
class SimpleQtspAuthorizationService private constructor(
    private val authorizationService: SimpleAuthorizationService,
) : OAuth2AuthorizationServerAdapter by authorizationService, AuthorizationService by authorizationService {
    @Deprecated("Use constructor without `dataProvider` instead")
    constructor(
        dataProvider: OAuth2DataProvider,
        acceptedCredentials: Collection<ConstantIndex.CredentialScheme>,
    ) : this(
        authorizationService = SimpleAuthorizationService(
            dataProvider = dataProvider,
            strategy = QtspAuthorizationServiceStrategy(
                authorizationServiceStrategy = CredentialAuthorizationServiceStrategy(
                    acceptedCredentials.toSet()
                )
            )
        )
    )

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