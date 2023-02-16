package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.CredentialSubject
import kotlinx.datetime.Instant

/**
 * Stores all issued credentials, keeps track of the index for the revocation list
 */
interface IssuerCredentialStore {

    /**
     * Called by the issuer when creating a new credential.
     * Expected to return a new index to use as a `statusListIndex`
     * Returns null if `vcId` is already registered
     */
    fun storeGetNextIndex(
        vcId: String,
        credentialSubject: CredentialSubject,
        issuanceDate: Instant,
        expirationDate: Instant,
        timePeriod: Int
    ): Long?

    /**
     * Returns a list of revoked credentials, represented by their `statusListIndex`
     */
    fun getRevokedStatusListIndexList(timePeriod: Int): Collection<Long>

    /**
     * Revoke the credential with this `vcId`, if it exists
     */
    fun revoke(vcId: String, timePeriod: Int): Boolean

}
