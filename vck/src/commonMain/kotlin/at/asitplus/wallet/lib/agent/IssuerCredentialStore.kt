package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.sha256
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialSubject
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.time.Instant

/**
 * Stores all issued credentials, keeps track of the index for the revocation list
 */
interface IssuerCredentialStore {

    @Deprecated("Use `createStatusListIndex` and `updateStoredCredential` instead")
    sealed class Credential {
        abstract val scheme: ConstantIndex.CredentialScheme
        abstract val vcId: String

        @Suppress("DEPRECATION")
        data class VcJwt(
            override val vcId: String,
            val credentialSubject: CredentialSubject,
            override val scheme: ConstantIndex.CredentialScheme,
        ) : Credential()

        @Suppress("DEPRECATION")
        data class VcSd(
            override val vcId: String,
            val claims: Collection<ClaimToBeIssued>,
            override val scheme: ConstantIndex.CredentialScheme,
        ) : Credential()

        @Suppress("DEPRECATION")
        data class Iso(
            val issuerSignedItemList: List<IssuerSignedItem>,
            override val scheme: ConstantIndex.CredentialScheme,
        ) : Credential() {
            override val vcId = issuerSignedItemList.toString()
                .encodeToByteArray().sha256().encodeToString(Base16Strict)
        }
    }

    data class StoredCredentialReference(
        val id: String,
        val timePeriod: Int,
        val statusListIndex: ULong,
    )

    /**
     * Called by the issuer when creating a new credential.
     * Expected to return a new index to use as a `statusListIndex`.
     * Returns null if `vcId` is already registered
     */
    @Suppress("DEPRECATION")
    @Deprecated("Use `createStatusListIndex` and `updateStoredCredential` instead")
    suspend fun storeGetNextIndex(
        credential: Credential,
        subjectPublicKey: CryptoPublicKey,
        issuanceDate: Instant,
        expirationDate: Instant,
        timePeriod: Int,
    ): Long?

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
     * Set the status of the credential with this `vcId`, if it exists
     */
    @Deprecated("Use setStatus(timePeriod, index, status) instead")
    fun setStatus(vcId: String, status: TokenStatus, timePeriod: Int): Boolean

    /**
     * Set the [status] of the credential with this [index] for the [timePeriod], if it exists
     */
    fun setStatus(timePeriod: Int, index: ULong, status: TokenStatus): Boolean
}