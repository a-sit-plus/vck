package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.CredentialSubject
import kotlin.time.Instant

/**
 * Provides data for credentials to be issued.
 */
interface IssuerCredentialDataProvider {

    /**
     * Gets called with the attribute name for atomic credentials, and the prefix
     * [at.asitplus.wallet.lib.data.SchemaIndex.ATTR_GENERIC_PREFIX].
     */
    fun getClaim(subjectId: String, attributeName: String): KmmResult<CredentialToBeIssued>

    /**
     * Gets called with the credential type, i.e. one of
     * [at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme.vcType]
     */
    fun getCredential(subjectId: String, attributeType: String): KmmResult<CredentialToBeIssued>

    data class CredentialToBeIssued(
        val subject: CredentialSubject,
        val expiration: Instant,
        val attributeType: String,
        val attachments: List<Issuer.Attachment>? = null,
    )

}
