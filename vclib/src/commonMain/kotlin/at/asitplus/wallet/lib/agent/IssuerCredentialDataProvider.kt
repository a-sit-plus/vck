package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.CredentialSubject
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
        attributeTypes: Collection<String>
    ): KmmResult<List<CredentialToBeIssued>>

    data class CredentialToBeIssued(
        val subject: CredentialSubject,
        val expiration: Instant,
        val attributeType: String,
        val attachments: List<Issuer.Attachment>? = null,
    )

}
