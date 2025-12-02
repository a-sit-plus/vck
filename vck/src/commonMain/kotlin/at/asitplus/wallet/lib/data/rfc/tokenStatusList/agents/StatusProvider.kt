package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListAggregation
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import kotlin.time.Instant

/**
 * The Status Issuer provides the Status List Token to the Status Provider, who serves the Status
 * List Token on a public, resolvable endpoint.
 */
interface StatusProvider<StatusListToken : Any> {
    /**
     * @return a status list based on the accepted and available types.
     */
    suspend fun provideStatusListToken(
        acceptedContentTypes: List<StatusListTokenMediaType>,
        time: Instant? = null,
        kind: RevocationList.Kind = RevocationList.Kind.STATUS_LIST,
    ): Pair<StatusListTokenMediaType, StatusListToken>

    /**
     * @return a status list based on the accepted and available types.
     */
    suspend fun provideStatusListAggregation(): StatusListAggregation
}



