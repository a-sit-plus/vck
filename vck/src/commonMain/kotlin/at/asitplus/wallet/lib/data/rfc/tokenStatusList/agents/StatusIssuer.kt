package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents

import kotlin.time.Instant

/**
 * The Issuer gives updated status information to the Status Issuer, who creates a Status List
 * Token. The Status Issuer provides the Status List Token to the Status Provider
 */
interface StatusIssuer<JsonSerialized: Any, CborSerialized: Any> {
    /**
     * @return a status list jwt.
     */
    suspend fun issueStatusListJwt(time: Instant? = null): JsonSerialized

    /**
     * @return a status list cwt.
     */
    suspend fun issueStatusListCwt(time: Instant? = null): CborSerialized
}