package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.cbor.CoseKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialSubject
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import kotlinx.datetime.Instant

/**
 * Provides data for credentials to be issued.
 */
interface IssuerCredentialDataProvider {

    /**
     * Gets called with a list of credential types, i.e. some of
     * [at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme.vcType]
     */
    fun getCredentialWithType(
        subjectId: String,
        subjectPublicKey: CryptoPublicKey? = null,
        attributeTypes: Collection<String>
    ): KmmResult<List<CredentialToBeIssued>>

}

sealed class CredentialToBeIssued {
    data class Vc(
        val subject: CredentialSubject,
        val expiration: Instant,
        val scheme: ConstantIndex.CredentialScheme,
        val attachments: List<Issuer.Attachment>? = null
    ) : CredentialToBeIssued()

    data class Iso(
        val issuerSignedItems: List<IssuerSignedItem>,
        val subjectPublicKey: CoseKey,
        val expiration: Instant,
        val scheme: ConstantIndex.CredentialScheme,
    ) : CredentialToBeIssued()
}
