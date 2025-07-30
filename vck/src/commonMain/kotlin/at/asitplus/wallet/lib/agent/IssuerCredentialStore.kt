package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus

/**
 * Stores all issued credentials, keeps track of the index for the revocation list
 */
interface IssuerCredentialStore {

    data class StoredCredentialReference(
        val id: String,
        val timePeriod: Int,
        val statusListIndex: ULong,
    )

    /**
     * Called by an [Issuer] when creating a new credential to get a `statusListIndex` first.
     * [Issuer] will call [updateStoredCredential] with the issued credential afterwards.
     */
    suspend fun createStatusListIndex(
        credential: CredentialToBeIssued,
        timePeriod: Int,
    ): KmmResult<StoredCredentialReference>

    /**
     * Called by an [Issuer] when the credential has been signed and delivered to the holder.
     */
    suspend fun updateStoredCredential(
        reference: StoredCredentialReference,
        credential: Issuer.IssuedCredential,
    ): KmmResult<StoredCredentialReference>

    /**
     * Returns a list of revoked credentials, represented by their `statusListIndex`
     */
    fun getStatusListView(timePeriod: Int): StatusListView

    /**
     * Set the [status] of the credential with this [index] for the [timePeriod], if it exists
     */
    fun setStatus(timePeriod: Int, index: ULong, status: TokenStatus): Boolean
}