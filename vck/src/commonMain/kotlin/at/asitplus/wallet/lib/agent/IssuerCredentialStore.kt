package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult

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
     * Called by an [Issuer] when creating a new credential to get a `statusListIndex` and `identifier first.
     * [Issuer] will call [updateStoredCredential] with the issued credential afterwards.
     */
    suspend fun createStoredCredentialReference(
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
}