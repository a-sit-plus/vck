package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialSubject
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.iso.IssuerSignedItem
import kotlinx.datetime.Instant

/**
 * Stores all issued credentials, keeps track of the index for the revocation list
 */
interface IssuerCredentialStore {

    sealed class Credential {
        data class VcJwt(
            val vcId: String,
            val credentialSubject: CredentialSubject,
            val scheme: ConstantIndex.CredentialScheme
        ) : Credential()

        data class VcSd(
            val vcId: String,
            val claims: Collection<ClaimToBeIssued>,
            val scheme: ConstantIndex.CredentialScheme
        ) : Credential()

        data class Iso(
            val issuerSignedItemList: List<IssuerSignedItem>,
            val scheme: ConstantIndex.CredentialScheme
        ) : Credential()
    }

    /**
     * Called by the issuer when creating a new credential.
     * Expected to return a new index to use as a `statusListIndex`
     * Returns null if `vcId` is already registered
     */
    suspend fun storeGetNextIndex(
        credential: Credential,
        subjectPublicKey: CryptoPublicKey,
        issuanceDate: Instant,
        expirationDate: Instant,
        timePeriod: Int
    ): Long?

    /**
     * Returns a list of revoked credentials, represented by their `statusListIndex`
     */
    fun getStatusListView(timePeriod: Int): StatusListView

    /**
     * Set the status of the credential with this `vcId`, if it exists
     */
    fun setStatus(vcId: String, status: TokenStatus, timePeriod: Int): Boolean
}
