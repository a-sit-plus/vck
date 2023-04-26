package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.CredentialSubject
import kotlinx.datetime.Instant

/**
 * Provides data for credentials to be issued.
 */
interface IssuerCredentialDataProvider {

    /**
     * Gets called with the attribute name for atomic credentials, and the prefix
     * [at.asitplus.wallet.lib.data.SchemaIndex.ATTR_GENERIC_PREFIX].
     */
    @Deprecated(message = "Use attribute types only and call `getCredentialWithType`")
    fun getClaim(subjectId: String, attributeName: String): KmmResult<CredentialToBeIssued>

    /**
     * Gets called with the credential type, i.e. one of
     * [at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme.vcType]
     */
    @Deprecated(message = "Use attribute types only and call `getCredentialWithType`")
    fun getCredential(subjectId: String, attributeType: String): KmmResult<CredentialToBeIssued>

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
