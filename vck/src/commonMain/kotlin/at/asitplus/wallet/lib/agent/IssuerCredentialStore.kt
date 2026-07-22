package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult

/**
 * Stores all issued credentials, keeps track of the index for the revocation list
 */
interface IssuerCredentialStore {

    @Deprecated("Use data class from `ReferencedTokenStore` instead")
    data class StoredCredentialReference(
        val id: String,
        val timePeriod: Int,
        val statusListIndex: ULong,
    )

    @Suppress("DEPRECATION")
    @Deprecated("Use method from `ReferencedTokenStore` instead")
    suspend fun createStoredCredentialReference(
        credential: CredentialToBeIssued,
        timePeriod: Int,
    ): KmmResult<StoredCredentialReference>

    @Suppress("DEPRECATION")
    @Deprecated("Issuer will call onCredentialStored instead")
    suspend fun updateStoredCredential(
        reference: StoredCredentialReference,
        credential: Issuer.IssuedCredential,
    ): KmmResult<StoredCredentialReference>

    /**
     * Called by an [Issuer] when the credential has been signed and delivered to the holder.
     */
    suspend fun onCredentialIssued(
        credential: Issuer.IssuedCredential,
    )
}