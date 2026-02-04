package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.ConstantIndex
import kotlin.time.Instant

/**
 * Stores all issued credentials, keeps track of the index for the revocation list
 */
interface IssuerCredentialStore {

    /**
     * Called by an [Issuer] when creating a new credential to get a `statusListIndex` first.
     * [Issuer] will call [storeCredential] with the issued credential afterwards.
     */
    suspend fun createStatusListIndex(
        timePeriod: Int,
    ): ULong

    /**
     * Called by an [Issuer] when the credential has been signed and delivered to the holder.
     */
    suspend fun storeCredential(
        timePeriod: Int,
        reference: ULong,
        validUntil: Instant,
        scheme: ConstantIndex.CredentialScheme
    ): KmmResult<Boolean>
}