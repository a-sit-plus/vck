package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus

/**
 * Stores all tokens that may be referenced to by a [at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView]
 */
interface ReferencedTokenStore {

    /**
     * Returns a list of the status of tokens, represented by their `statusListIndex` for that [timePeriod].
     */
    fun getStatusListView(timePeriod: Int): StatusListView

    /**
     * Set the [status] of the referenced token with this [index] for the [timePeriod], if it exists.
     */
    fun setStatus(timePeriod: Int, index: ULong, status: TokenStatus): Boolean
}