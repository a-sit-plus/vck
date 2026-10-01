package at.asitplus.wallet.lib.agent

/**
 * Stores all issued credentials, keeps track of the index for the revocation list
 */
interface IssuerCredentialStore {

    /**
     * Called by an [Issuer] when the credential has been signed and delivered to the holder.
     */
    suspend fun onCredentialIssued(
        credential: Issuer.IssuedCredential,
    )
}
