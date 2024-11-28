package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents

/**
 * The Issuer gives updated status information to the Status Issuer, who creates a Status List
 * Token. The Status Issuer provides the Status List Token to the Status Provider
 */
interface StatusIssuer<JsonSerialized: Any, CborSerialized: Any> {
    /**
     * @return a status list jwt.
     */
    suspend fun issueStatusListJwt(): JsonSerialized

    /**
     * @return a status list json string.
     */
    suspend fun issueStatusListJson(): JsonSerialized

    /**
     * @return a status list cwt.
     */
    suspend fun issueStatusListCwt(): CborSerialized

    /**
     * @return a status list cbor byte array.
     */
    suspend fun issueStatusListCbor(): CborSerialized
}