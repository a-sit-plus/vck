package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.StatusIssuer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.StatusProvider

/**
 * Summarizes operations for a Status Issuer in the sense of
 * [Token Status List (TSL)](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html).
 *
 * See also [at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus].
 *
 * It manages the Status List (which describe status of referenced tokens, mostly verifiable credentials),
 * and issue Status List Tokens (which embed the status list).
 */
interface StatusListIssuer : StatusIssuer, StatusProvider {

    /**
     * Returns a revocation list which can either be status list as defined in
     * [Token Status List](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html)
     * or an identifier list as defined in ISO/IEC 18013-5:2021.
     */
    fun buildRevocationList(
        timePeriod: Int? = null,
        kind: RevocationList.Kind = RevocationList.Kind.STATUS_LIST
    ): RevocationList?

    /**
     * Sets the status of one specific credential to
     * [at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus.Invalid].
     * Returns `true` if this credential has been revoked.
     */
    fun revokeCredentialByIndex(timePeriod: Int, statusListIndex: ULong): Boolean

    /**
     * For JVM callers: Sets the status of one specific credential to
     * [at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus.Invalid].
     * Returns `true` if this credential has been revoked.
     */
    fun revokeCredentialByIndexLong(timePeriod: Int, statusListIndex: Long): Boolean =
        revokeCredentialByIndex(timePeriod, statusListIndex.toULong().also {
            require(statusListIndex >= 0) { "statusListIndex must be non-negative" }
        })

    /**
     * Sets the status of one specific credential to
     * [at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus.Invalid].
     * Returns `true` if this credential has been revoked.
     */
    fun revokeCredentialByIdentifier(timePeriod: Int, identifier: ByteArray): Boolean

}