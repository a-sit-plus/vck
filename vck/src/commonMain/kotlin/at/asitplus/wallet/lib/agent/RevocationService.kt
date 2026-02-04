package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.Identifier
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import kotlin.Boolean

/**
 * Storage abstraction for revocation data grouped by a time period (for example, an epoch day).
 * Implementations are responsible for creating entries, updating their status, and building the
 * corresponding [RevocationList] for transport.
 *
 * Type parameters:
 *  R: Concrete list representation, e.g. [StatusList] or [IdentifierList]
 *  I: Identifier used to reference entries in [R]. This is implementation-defined and depends on internal representation.
 *     Examples:
 *      - For [StatusList] this may be the position in the uncompressed StatusList
 *      - For [IdentifierList] this may be [Identifier] or [ByteArray]
 */
interface RevocationService<R: RevocationList, I> {

    /**
     * Create a new entry for [timePeriod] and return its identifier for later updates.
     */
    suspend fun createEntry(timePeriod: Int) : I

    /**
     * Tries to update the status of an entry identified by [identifier] for [timePeriod].
     * Returns true on success/false otherwise
     *
     * Note that [StatusList] allows for status updates at the index, [IdentifierList] however only supports revocation
     * via adding [identifier] to the revocation list.
     */
    suspend fun updateEntry(timePeriod: Int, identifier: I, tokenStatus: TokenStatus) : Boolean

    /**
     * Build the revocation list for [timePeriod] in its specification-defined format.
     */
    suspend fun getRevocationList(timePeriod: Int): R
}