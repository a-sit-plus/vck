package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialSubject
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import kotlinx.datetime.Instant

/**
 * Provides data for credentials to be issued.
 */
interface IssuerCredentialDataProvider {

    /**
     * Gets called with a resolved [credentialScheme], the holder key in [subjectPublicKey] and the requested
     * credential [representation]
     */
    fun getCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
    ): KmmResult<List<CredentialToBeIssued>>
}

sealed class CredentialToBeIssued {
    data class VcJwt(
        val subject: CredentialSubject,
        val expiration: Instant,
        val attachments: List<Issuer.Attachment>? = null
    ) : CredentialToBeIssued()

    data class VcSd(
        val claims: Collection<ClaimToBeIssued>,
        val expiration: Instant,
    ) : CredentialToBeIssued()

    data class Iso(
        val issuerSignedItems: List<IssuerSignedItem>,
        val expiration: Instant,
    ) : CredentialToBeIssued()
}

data class ClaimToBeIssued(val name: String, val value: String)