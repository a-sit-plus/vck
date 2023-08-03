package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.cbor.CoseAlgorithm
import at.asitplus.wallet.lib.cbor.CoseHeader
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.iso.DeviceAuth
import at.asitplus.wallet.lib.iso.DeviceSigned
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DOC_TYPE_MDL
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.NAMESPACE_MDL
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.iso.IssuerSignedList
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import io.github.aakira.napier.Napier
import kotlinx.serialization.cbor.ByteStringWrapper


/**
 * An agent that only implements [Holder], i.e. it can receive credentials form other agents
 * and present credentials to other agents.
 */
class HolderAgent(
    private val validator: Validator = Validator.newDefaultInstance(),
    private val subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore(),
    private val jwsService: JwsService,
    private val coseService: CoseService,
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
            coseService = DefaultCoseService(cryptoService),
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
            coseService = DefaultCoseService(cryptoService),
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
        val acceptedIso = mutableListOf<IssuerSigned>()
        val rejected = mutableListOf<String>()
        val attachments = mutableListOf<Holder.StoredAttachmentResult>()
        credentialList.filterIsInstance<Holder.StoreCredentialInput.Vc>().forEach { cred ->
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

                else -> {}
            }
        }
        credentialList.filterIsInstance<Holder.StoreCredentialInput.Iso>().forEach { cred ->
            val issuerKey = cred.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.let {
                CryptoUtils.extractCoseKeyFromX509Cert(it)
            }
            when (val result = validator.verifyIsoCred(cred.issuerSigned, issuerKey)) {
                is Verifier.VerifyCredentialResult.InvalidStructure -> rejected += result.input
                is Verifier.VerifyCredentialResult.Revoked -> rejected += result.input
                is Verifier.VerifyCredentialResult.SuccessIso -> acceptedIso += result.issuerSigned
                    .also { subjectCredentialStore.storeCredential(result.issuerSigned) }

                else -> {}
            }
        }
        return Holder.StoredCredentialsResult(
            accepted = accepted,
            acceptedIso = acceptedIso,
            rejected = rejected,
            attachments = attachments
        )
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
        attributeTypes: Collection<String>?,
    ): Collection<Holder.StoredCredential>? {
        val credentials = subjectCredentialStore.getCredentials(attributeTypes).getOrNull()
            ?: return null
                .also { Napier.w("Got no credentials from subjectCredentialStore") }
        return credentials.map {
            when (it) {
                is SubjectCredentialStore.StoreEntry.Iso -> Holder.StoredCredential.Iso(it.issuerSigned)
                is SubjectCredentialStore.StoreEntry.Vc -> Holder.StoredCredential.Vc(
                    it.vcSerialized,
                    it.vc,
                    validator.checkRevocationStatus(it.vc)
                )
            }
        }
    }

    /**
     * Creates a [VerifiablePresentation] serialized as a JWT for all the credentials we have stored,
     * that match [attributeTypes] (if specified). Optionally filters by [requestedClaims] (e.g. in ISO case).
     *
     * May return null if no valid credentials (i.e. non-revoked, matching attribute name) are available.
     */
    override suspend fun createPresentation(
        challenge: String,
        audienceId: String,
        attributeTypes: Collection<String>?,
        requestedClaims: Collection<String>?,
    ): Holder.CreatePresentationResult? {
        val credentials = subjectCredentialStore.getCredentials(attributeTypes).getOrNull()
            ?: return null
                .also { Napier.w("Got no credentials from subjectCredentialStore") }
        val validVcCredentials = credentials
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            .filter { validator.checkRevocationStatus(it.vc) != Validator.RevocationStatus.REVOKED }
            .map { it.vcSerialized }
        if (validVcCredentials.isNotEmpty()) {
            return createPresentation(validVcCredentials, challenge, audienceId)
        }
        val validIsoCredential = credentials
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Iso>()
            // no revocation check
            .map { it.issuerSigned }
            .firstOrNull()
        if (validIsoCredential != null) {
            val deviceSignature = coseService.createSignedCose(
                protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
                unprotectedHeader = null,
                payload = challenge.encodeToByteArray(),
                addKeyId = false
            ).getOrNull() ?: return null
                .also { Napier.w("Could not create DeviceAuth for presentation") }
            val attributes = validIsoCredential.namespaces?.get(NAMESPACE_MDL)
                ?: return null
                    .also { Napier.w("Could not filter issuerSignedItems for $NAMESPACE_MDL") }
            return Holder.CreatePresentationResult.Document(
                Document(
                    docType = DOC_TYPE_MDL,
                    issuerSigned = IssuerSigned(
                        namespaces = mapOf(NAMESPACE_MDL to IssuerSignedList(attributes.entries.filter {
                            it.discloseItem(requestedClaims)
                        })),
                        issuerAuth = validIsoCredential.issuerAuth
                    ),
                    deviceSigned = DeviceSigned(
                        namespaces = byteArrayOf(),
                        deviceAuth = DeviceAuth(
                            deviceSignature = deviceSignature
                        )
                    )
                )
            )
        }
        Napier.w("Got no valid credentials for $attributeTypes")
        return null
    }

    private fun ByteStringWrapper<IssuerSignedItem>.discloseItem(requestedClaims: Collection<String>?) =
        if (requestedClaims?.isNotEmpty() == true) {
            value.elementIdentifier in requestedClaims
        } else {
            true
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
                .also { Napier.w("Could not create JWS for presentation") }
        return Holder.CreatePresentationResult.Signed(jws)
    }


}
