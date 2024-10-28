package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialSubject
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import kotlinx.datetime.Instant

sealed class CredentialToBeIssued {
    data class VcJwt(
        val subject: CredentialSubject,
        val expiration: Instant,
        val scheme: ConstantIndex.CredentialScheme,
        val subjectPublicKey: CryptoPublicKey,
    ) : CredentialToBeIssued()

    data class VcSd(
        val claims: Collection<ClaimToBeIssued>,
        val expiration: Instant,
        val scheme: ConstantIndex.CredentialScheme,
        val subjectPublicKey: CryptoPublicKey,
    ) : CredentialToBeIssued()

    data class Iso(
        val issuerSignedItems: List<IssuerSignedItem>,
        val expiration: Instant,
        val scheme: ConstantIndex.CredentialScheme,
        val subjectPublicKey: CryptoPublicKey,
    ) : CredentialToBeIssued()
}

/**
 * Represents a claim that shall be issued to the holder,
 * i.e. serialized into the appropriate credential format.
 * To issue nested structures in SD-JWT, pass a Collection of [ClaimToBeIssued] in [value].
 */
data class ClaimToBeIssued(val name: String, val value: Any, val selectivelyDisclosable: Boolean = true)
