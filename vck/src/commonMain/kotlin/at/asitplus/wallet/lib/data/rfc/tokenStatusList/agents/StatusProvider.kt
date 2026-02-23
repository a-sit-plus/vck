package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents

import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListAggregation
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import kotlin.time.Instant

/**
 * The Status Issuer provides the Status List Token to the Status Provider, who serves the Status
 * List Token on a public, resolvable endpoint.
 */
interface StatusProvider {
    /**
     * @return a status list based on the accepted and available types.
     */
    suspend fun provideStatusListToken(
        acceptedContentTypes: List<StatusListTokenMediaType>,
        time: Instant? = null,
        kind: RevocationList.Kind = RevocationList.Kind.STATUS_LIST,
    ): Pair<StatusListTokenMediaType, StatusListToken>

    /**
     * The Status List Aggregation URI provides a list of Status List Token
     * URIs.  This aggregation is in JSON and the returned media type MUST
     * be application/json.  A Relying Party can iterate through this list
     * and fetch all Status List Tokens before encountering the specific URI
     * in a Referenced Token.
     *
     * Contains all URIs corresponding to [StatusList]
     */
    suspend fun provideStatusListAggregation(): StatusListAggregation


    /**
     * The Status List Aggregation URI provides a list of Status List Token
     * URIs.  This aggregation is in JSON and the returned media type MUST
     * be application/json.  A Relying Party can iterate through this list
     * and fetch all Status List Tokens before encountering the specific URI
     * in a Referenced Token.
     *
     * Contains all URIs corresponding to [IdentifierList]
     */
    suspend fun provideIdentifierListAggregation(): StatusListAggregation
}



