package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType

/**
 * The Status Issuer provides the Status List Token to the Status Provider, who serves the Status
 * List Token on a public, resolvable endpoint.
 */
interface StatusProvider<StatusListToken: Any> {
    /**
     * @return a status list based on the accepted and available types.
     */
    suspend fun provideStatusList(acceptedContentTypes: List<StatusListTokenMediaType>): StatusListToken
}