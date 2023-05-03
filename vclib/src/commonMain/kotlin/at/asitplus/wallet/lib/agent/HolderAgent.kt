package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import io.github.aakira.napier.Napier


/**
 * An agent that only implements [Holder], i.e. it can receive credentials form other agents
 * and present credentials to other agents.
 */
class HolderAgent constructor(
    private val validator: Validator = Validator.newDefaultInstance(),
    private val subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore(),
    private val jwsService: JwsService,
    override val identifier: String
) : Holder {

    companion object {
        fun newDefaultInstance(
            cryptoService: CryptoService = DefaultCryptoService(),
            verifierCryptoService: VerifierCryptoService = DefaultVerifierCryptoService(),
            subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore(),
        ) = HolderAgent(
            validator = Validator.newDefaultInstance(verifierCryptoService, Parser()),
            subjectCredentialStore = subjectCredentialStore,
            jwsService = DefaultJwsService(cryptoService),
            identifier = cryptoService.identifier,
        )

        /**
         * Explicitly short argument list to use it from Swift
         */
        fun newDefaultInstance(
            cryptoService: CryptoService = DefaultCryptoService(),
            subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore(),
        ) = HolderAgent(
            validator = Validator.newDefaultInstance(DefaultVerifierCryptoService(), Parser()),
            subjectCredentialStore = subjectCredentialStore,
            jwsService = DefaultJwsService(cryptoService),
            identifier = cryptoService.identifier,
        )
    }

    /**
     * Sets the revocation list ot use for further processing of Verifiable Credentials
     *
     * @return `true` if the revocation list has been validated and set, `false` otherwise
     */
    override fun setRevocationList(it: String): Boolean {
        return validator.setRevocationList(it)
    }

    /**
     * Stores all verifiable credentials from [credentialList] that parse and validate,
     * and returns them for future reference.
     *
     * Note: Revocation credentials should not be stored, but set with [setRevocationList].
     */
    override suspend fun storeCredentials(credentialList: List<Holder.StoreCredentialInput>): Holder.StoredCredentialsResult {
        val accepted = mutableListOf<VerifiableCredentialJws>()
        val rejected = mutableListOf<String>()
        val attachments = mutableListOf<Holder.StoredAttachmentResult>()
        credentialList.forEach { cred ->
            when (val vc = validator.verifyVcJws(cred.vcJws, identifier)) {
                is Verifier.VerifyCredentialResult.InvalidStructure -> rejected += vc.input
                is Verifier.VerifyCredentialResult.Revoked -> rejected += vc.input
                is Verifier.VerifyCredentialResult.Success -> accepted += vc.jws
                    .also { subjectCredentialStore.storeCredential(it, cred.vcJws) }
                    .also {
                        cred.attachments?.forEach { attachment ->
                            subjectCredentialStore.storeAttachment(attachment.name, attachment.data, it.vc.id)
                                .also { attachments += Holder.StoredAttachmentResult(attachment.name, attachment.data) }
                        }
                    }
            }
        }
        return Holder.StoredCredentialsResult(accepted = accepted, rejected = rejected, attachments = attachments)
    }

    /**
     * Stores all verifiable credentials from [credentialList].
     * _Does not validate the credentials!_
     */
    @Suppress("unused")
    override suspend fun storeValidatedCredentials(credentialList: List<Holder.ValidatedVerifiableCredentialJws>): Boolean {
        credentialList.forEach {
            subjectCredentialStore.storeCredential(it.vc, it.serialized)
        }
        return true
    }

    /**
     * Gets a list of all stored credentials, with a revocation status.
     *
     * Note that the revocation status may be [Validator.RevocationStatus.UNKNOWN] if no revocation list
     * has been set with [setRevocationList]
     */
    override suspend fun getCredentials(
        attributeNames: List<String>?,
        attributeTypes: List<String>?,
    ): List<Holder.StoredCredential>? {
        val credentials =
            subjectCredentialStore.getCredentials(attributeTypes, attributeNames).getOrNull()
                ?: return null
                    .also { Napier.w("Got no credentials from subjectCredentialStore") }
        return credentials.map {
            Holder.StoredCredential(it.vcSerialized, it.vc, validator.checkRevocationStatus(it.vc))
        }
    }

    /**
     * Creates a [VerifiablePresentation] serialized as a JWT for all the credentials we have stored,
     * that match the [attributeNames] or [attributeTypes] (if specified).
     *
     * May return null if no valid credentials (i.e. non-revoked, matching attribute name) are available.
     */
    override suspend fun createPresentation(
        challenge: String,
        audienceId: String,
        attributeNames: List<String>?,
        attributeTypes: List<String>?,
    ): Holder.CreatePresentationResult? {
        val credentials =
            subjectCredentialStore.getCredentials(attributeTypes, attributeNames).getOrNull()
                ?: return null
                    .also { Napier.w("Got no credentials from subjectCredentialStore") }
        val validCredentials = credentials
            .filter { validator.checkRevocationStatus(it.vc) != Validator.RevocationStatus.REVOKED }
            .map { it.vcSerialized }
        if (validCredentials.isEmpty()) return null
            .also { Napier.w("Got no valid credentials") }
        return createPresentation(validCredentials, challenge, audienceId)
    }

    /**
     * Creates a [VerifiablePresentation] with the given [validCredentials].
     *
     * Note: The caller is responsible that only valid credentials are passed to this function!
     */
    override suspend fun createPresentation(
        validCredentials: List<String>,
        challenge: String,
        audienceId: String,
    ): Holder.CreatePresentationResult? {
        val vp = VerifiablePresentation(validCredentials.toTypedArray())
        val vpSerialized = vp.toJws(challenge, identifier, audienceId).serialize()
        val jwsPayload = vpSerialized.encodeToByteArray()
        val jws = jwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload)
            ?: return null
        return Holder.CreatePresentationResult.Signed(jws)
    }


}
