package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialSubject
import at.asitplus.iso.IssuerSignedItem
import kotlinx.datetime.Instant

sealed class CredentialToBeIssued {
    abstract val expiration: Instant
    abstract val scheme: ConstantIndex.CredentialScheme
    abstract val subjectPublicKey: CryptoPublicKey

    data class VcJwt(
        val subject: CredentialSubject,
        override val expiration: Instant,
        override val scheme: ConstantIndex.CredentialScheme,
        override val subjectPublicKey: CryptoPublicKey,
    ) : CredentialToBeIssued()

    data class VcSd(
        val claims: Collection<ClaimToBeIssued>,
        override val expiration: Instant,
        override val scheme: ConstantIndex.CredentialScheme,
        override val subjectPublicKey: CryptoPublicKey,
    ) : CredentialToBeIssued()

    data class Iso(
        val issuerSignedItems: List<IssuerSignedItem>,
        override val expiration: Instant,
        override val scheme: ConstantIndex.CredentialScheme,
        override val subjectPublicKey: CryptoPublicKey,
    ) : CredentialToBeIssued()
}

/**
 * Represents a claim that shall be issued to the holder, i.e. serialized into the appropriate credential format.
 *
 * To issue nested structures in SD-JWT, pick one of two options:
 * - Pass a collection of [ClaimToBeIssued] in [value].
 * - Put dots `.` in [name], e.g. `address.region`
 *
 * For each claim, one can select if the claim shall be selectively disclosable, or otherwise included plain.
 */
data class ClaimToBeIssued(val name: String, val value: Any, val selectivelyDisclosable: Boolean = true)
