package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.Identifier
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.IdentifierInfo
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
     * Returns a list of the status of tokens, represented by their `identifier` for that [timePeriod].
     * All elements in the list are revoked. All others are assumed [TokenStatus.Valid]
     */
    fun getRawIdentifierList(timePeriod: Int): Map<Identifier, IdentifierInfo>

    /**
     * Set the [status] of the referenced token with this [index] for the [timePeriod], if it exists.
     */
    fun setStatus(timePeriod: Int, index: ULong, status: TokenStatus): Boolean

    /**
     * Set the status of the referenced token with this [identifier] for the [timePeriod] to revoked, if it exists.
     * Other operations are not supported in the spec.
     */
    fun revokeIdentifier(timePeriod: Int, identifier: ByteArray): Boolean
}