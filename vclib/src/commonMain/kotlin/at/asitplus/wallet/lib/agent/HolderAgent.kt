package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.cose.CoseKey
import at.asitplus.crypto.datatypes.cose.toCoseKey
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.InputEvaluator
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.PresentationSubmission
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionDescriptor
import at.asitplus.wallet.lib.data.dif.StandardInputEvaluator
import at.asitplus.wallet.lib.data.jsonSerializer
import at.asitplus.wallet.lib.iso.DeviceAuth
import at.asitplus.wallet.lib.iso.DeviceSigned
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.ElementValue
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.iso.IssuerSignedList
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlinx.serialization.cbor.ByteStringWrapper
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject


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
            identifier = cryptoService.publicKey.didEncoded,
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
            identifier = cryptoService.publicKey.didEncoded,
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
        val acceptedVcJwt = mutableListOf<VerifiableCredentialJws>()
        val acceptedSdJwt = mutableListOf<VerifiableCredentialSdJwt>()
        val acceptedIso = mutableListOf<IssuerSigned>()
        val rejected = mutableListOf<String>()
        val attachments = mutableListOf<Holder.StoredAttachmentResult>()
        credentialList.filterIsInstance<Holder.StoreCredentialInput.Vc>().forEach { cred ->
            when (val vc = validator.verifyVcJws(cred.vcJws, identifier)) {
                is Verifier.VerifyCredentialResult.InvalidStructure -> rejected += vc.input
                is Verifier.VerifyCredentialResult.Revoked -> rejected += vc.input
                is Verifier.VerifyCredentialResult.SuccessJwt -> acceptedVcJwt += vc.jws
                    .also { subjectCredentialStore.storeCredential(it, cred.vcJws, cred.scheme) }
                    .also {
                        cred.attachments?.forEach { attachment ->
                            subjectCredentialStore.storeAttachment(
                                attachment.name,
                                attachment.data,
                                it.vc.id
                            )
                                .also {
                                    attachments += Holder.StoredAttachmentResult(
                                        attachment.name,
                                        attachment.data
                                    )
                                }
                        }
                    }

                else -> {}
            }
        }
        credentialList.filterIsInstance<Holder.StoreCredentialInput.SdJwt>().forEach { cred ->
            when (val vc = validator.verifySdJwt(cred.vcSdJwt, identifier)) {
                is Verifier.VerifyCredentialResult.InvalidStructure -> rejected += vc.input
                is Verifier.VerifyCredentialResult.Revoked -> rejected += vc.input
                is Verifier.VerifyCredentialResult.SuccessSdJwt -> acceptedSdJwt += vc.sdJwt
                    .also {
                        subjectCredentialStore.storeCredential(
                            it,
                            cred.vcSdJwt,
                            vc.disclosures,
                            cred.scheme
                        )
                    }

                else -> {}
            }
        }
        credentialList.filterIsInstance<Holder.StoreCredentialInput.Iso>().forEach { cred ->
            val issuerKey: CoseKey? =
                cred.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain
                    ?.let {
                        runCatching { X509Certificate.decodeFromDer(it) }
                            .getOrNull()
                            ?.publicKey
                            ?.toCoseKey()
                            ?.getOrNull()
                    }

            when (val result = validator.verifyIsoCred(cred.issuerSigned, issuerKey)) {
                is Verifier.VerifyCredentialResult.InvalidStructure -> rejected += result.input
                is Verifier.VerifyCredentialResult.Revoked -> rejected += result.input
                is Verifier.VerifyCredentialResult.SuccessIso -> acceptedIso += result.issuerSigned
                    .also {
                        subjectCredentialStore.storeCredential(
                            result.issuerSigned,
                            cred.scheme
                        )
                    }

                else -> {}
            }
        }
        return Holder.StoredCredentialsResult(
            acceptedVcJwt = acceptedVcJwt,
            acceptedSdJwt = acceptedSdJwt,
            acceptedIso = acceptedIso,
            rejected = rejected,
            attachments = attachments
        )
    }


    /**
     * Gets a list of all stored credentials, with a revocation status.
     *
     * Note that the revocation status may be [Validator.RevocationStatus.UNKNOWN] if no revocation list
     * has been set with [setRevocationList]
     */
    override suspend fun getCredentials(): Collection<Holder.StoredCredential>? {
        val credentials = subjectCredentialStore.getCredentials().getOrNull()
            ?: return null
                .also { Napier.w("Got no credentials from subjectCredentialStore") }
        return credentials.map {
            when (it) {
                is SubjectCredentialStore.StoreEntry.Iso -> Holder.StoredCredential.Iso(
                    storeEntry = it,
                    status = Validator.RevocationStatus.UNKNOWN
                )

                is SubjectCredentialStore.StoreEntry.Vc -> Holder.StoredCredential.Vc(
                    storeEntry = it,
                    status = validator.checkRevocationStatus(it.vc)
                )

                is SubjectCredentialStore.StoreEntry.SdJwt -> Holder.StoredCredential.SdJwt(
                    storeEntry = it,
                    status = validator.checkRevocationStatus(it.sdJwt)
                )
            }
        }
    }

    override suspend fun createPresentation(
        challenge: String,
        audienceId: String,
        presentationDefinition: PresentationDefinition,
    ): KmmResult<Holder.HolderResponseParameters> {
        // an attempt to implement input evaluation and submission according to:
        // - https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation
        val inputs = getCredentials()?.filter {
            it.status != Validator.RevocationStatus.REVOKED
        }?.map { it.storeEntry }?.sortedBy {
            // prefer iso credentials and sd jwt credentials over plain vc credentials
            // -> they support selective disclosure!
            when (it) {
                is SubjectCredentialStore.StoreEntry.Vc -> 2
                is SubjectCredentialStore.StoreEntry.SdJwt -> 1
                is SubjectCredentialStore.StoreEntry.Iso -> 1
            }
        } ?: return KmmResult.failure(CredentialRetrievalException())

        data class CandidateInputMatchContainer(
            val inputDescriptor: InputDescriptor,
            val credential: SubjectCredentialStore.StoreEntry,
            val inputMatch: InputEvaluator.CandidateInputMatch,
        )

        val matches = presentationDefinition.inputDescriptors.map { inputDescriptor ->
            inputs.filter { credential ->
                // assume credential format to be supported by the verifier if no format holder is specified
                val supportedFormats = inputDescriptor.format ?: presentationDefinition.formats
                supportedFormats?.let { formatHolder ->
                    when (credential) {
                        is SubjectCredentialStore.StoreEntry.Vc -> formatHolder.jwtVp != null
                        is SubjectCredentialStore.StoreEntry.SdJwt -> formatHolder.jwtSd != null
                        is SubjectCredentialStore.StoreEntry.Iso -> formatHolder.msoMdoc != null
                    }
                } ?: true
            }.firstNotNullOfOrNull { credential ->
                StandardInputEvaluator().evaluateMatch(
                    inputDescriptor = inputDescriptor,
                    credential = credential.toJsonElement(),
                ).getOrNull()?.let {
                    CandidateInputMatchContainer(
                        inputDescriptor = inputDescriptor,
                        inputMatch = it,
                        credential = credential,
                    )
                }
            } ?: return KmmResult.failure(MissingInputDescriptorMatchException(inputDescriptor))
        }

        val presentationSubmission = PresentationSubmission(
            id = uuid4().toString(),
            definitionId = presentationDefinition.id,
            descriptorMap = matches.mapIndexed { index, match ->
                PresentationSubmissionDescriptor(
                    id = match.inputDescriptor.id,
                    format = when (match.credential) {
                        is SubjectCredentialStore.StoreEntry.Vc -> ClaimFormatEnum.JWT_VP
                        is SubjectCredentialStore.StoreEntry.SdJwt -> ClaimFormatEnum.JWT_SD
                        is SubjectCredentialStore.StoreEntry.Iso -> ClaimFormatEnum.MSO_MDOC
                    },
                    // from https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1-2.4
                    // These objects contain a field called path, which, for this specification,
                    // MUST have the value $ (top level root path) when only one Verifiable Presentation is contained in the VP Token,
                    // and MUST have the value $[n] (indexed path from root) when there are multiple Verifiable Presentations,
                    // where n is the index to select.
                    path = if (matches.size == 1) "\$" else "\$[$index]",
                )
            }
        )

        val verifiablePresentations = matches.map { match ->
            val requestedClaims =
                match.inputMatch.fieldQueryResults?.mapNotNull { fieldQueryResult ->
                    // TODO: find good way to transform the field query result paths into claim paths
                    // for now it should be sufficient to take the last part
                    fieldQueryResult?.jsonPath?.last()
                } ?: listOf()

            when (match.credential) {
                is SubjectCredentialStore.StoreEntry.Vc -> createVcPresentation(
                    challenge = challenge,
                    audienceId = audienceId,
                    validCredentials = listOf(match.credential.vcSerialized)
                )

                is SubjectCredentialStore.StoreEntry.SdJwt -> createSdJwtPresentation(
                    challenge = challenge,
                    audienceId = audienceId,
                    validSdJwtCredential = match.credential,
                    requestedClaims = requestedClaims
                )

                is SubjectCredentialStore.StoreEntry.Iso -> createIsoPresentation(
                    challenge = challenge,
                    credential = match.credential,
                    requestedClaims = requestedClaims
                )
            } ?: return KmmResult.failure(
                CredentialPresentationException(
                    credential = match.credential,
                    inputDescriptor = match.inputDescriptor,
                    candidateInputMatch = match.inputMatch,
                )
            )
        }

        return KmmResult.success(
            Holder.HolderResponseParameters(
                presentationSubmission = presentationSubmission,
                verifiablePresentations = verifiablePresentations,
            )
        )
    }

    private suspend fun createIsoPresentation(
        challenge: String,
        credential: SubjectCredentialStore.StoreEntry.Iso,
        requestedClaims: Collection<String>?
    ): Holder.CreatePresentationResult.Document? {
        val deviceSignature = coseService.createSignedCose(
            payload = challenge.encodeToByteArray(),
            addKeyId = false
        ).getOrNull() ?: return null
            .also { Napier.w("Could not create DeviceAuth for presentation") }
        val attributes = credential.issuerSigned.namespaces?.get(credential.scheme.isoNamespace)
            ?: return null
                .also { Napier.w("Could not filter issuerSignedItems for ${credential.scheme.isoNamespace}") }
        return Holder.CreatePresentationResult.Document(
            Document(
                docType = credential.scheme.isoDocType,
                issuerSigned = IssuerSigned(
                    namespaces = mapOf(
                        credential.scheme.isoNamespace to
                                IssuerSignedList(attributes.entries.filter {
                                    it.discloseItem(
                                        requestedClaims
                                    )
                                })
                    ),
                    issuerAuth = credential.issuerSigned.issuerAuth
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

    private suspend fun createSdJwtPresentation(
        audienceId: String,
        challenge: String,
        validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
        requestedClaims: Collection<String>?
    ): Holder.CreatePresentationResult.SdJwt? {
        // TODO can only be one credential at a time
        val keyBindingJws = KeyBindingJws(
            issuedAt = Clock.System.now(),
            audience = audienceId,
            challenge = challenge
        )
        val jwsPayload = keyBindingJws.serialize().encodeToByteArray()
        val keyBinding =
            jwsService.createSignedJwt(JwsContentTypeConstants.KB_JWT, jwsPayload).getOrElse {
                Napier.w("Could not create JWS for presentation", it)
                return null
            }
        val filteredDisclosures = validSdJwtCredential.disclosures
            .filter { it.discloseItem(requestedClaims) }.keys
        val sdJwt =
            (listOf(validSdJwtCredential.vcSerialized.substringBefore("~")) + filteredDisclosures + keyBinding.serialize())
                .joinToString("~")
        return Holder.CreatePresentationResult.SdJwt(sdJwt)
    }


    private fun Map.Entry<String, SelectiveDisclosureItem?>.discloseItem(requestedClaims: Collection<String>?) =
        if (requestedClaims?.isNotEmpty() == true) {
            value?.let { it.claimName in requestedClaims } ?: false
        } else {
            true
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
    override suspend fun createVcPresentation(
        validCredentials: List<String>,
        challenge: String,
        audienceId: String,
    ): Holder.CreatePresentationResult? {
        val vp = VerifiablePresentation(validCredentials)
        val vpSerialized = vp.toJws(challenge, identifier, audienceId).serialize()
        val jwsPayload = vpSerialized.encodeToByteArray()
        val jws = jwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload).getOrElse {
            Napier.w("Could not create JWS for presentation", it)
            return null
        }
        return Holder.CreatePresentationResult.Signed(jws.serialize())
    }
}

// in openid4vp, the claims to be presented are described using a JSONPath, so compiling this to a JsonElement seems fine
fun SubjectCredentialStore.StoreEntry.toJsonElement(): JsonElement {
    val credential = this
    return when (credential) {
        is SubjectCredentialStore.StoreEntry.Vc -> {
            buildJsonObject {
                put("type", JsonPrimitive(credential.scheme.vcType))
                jsonSerializer.encodeToJsonElement(credential.vc.vc.credentialSubject).jsonObject.entries.forEach {
                    put(it.key, it.value)
                }
                // TODO: Remove the rest here when there is a clear specification on how to encode vc credentials
                //  This may actually depend on the presentation context, so more information may be required
                put("vc", buildJsonArray {
                    add(jsonSerializer.encodeToJsonElement(credential.vc.vc.credentialSubject))
                })
            }
        }

        is SubjectCredentialStore.StoreEntry.SdJwt -> {
            val pairs = credential.disclosures.map {
                it.value?.let {
                    Pair(
                        it.claimName, when (val value = it.claimValue) {
                            is Boolean -> JsonPrimitive(value)
                            is Number -> JsonPrimitive(value)
                            else -> JsonPrimitive(it.claimValue.toString())
                        }
                    )
                }
            }.filterNotNull().toMap()
            buildJsonObject {
                put("type", JsonPrimitive(credential.scheme.vcType))
                pairs.forEach {
                    put(it.key, it.value)
                }
            }
        }

        is SubjectCredentialStore.StoreEntry.Iso -> {
            buildJsonObject {
                put("mdoc", buildJsonObject {
                    put("doctype", JsonPrimitive(credential.scheme.isoDocType))
                    // TODO: remove the rest here as soon as the eudiw verifier has found a better way to specify their presentation definition
                    put("namespace", JsonPrimitive(credential.scheme.isoNamespace))
                    credential.issuerSigned.namespaces?.forEach {
                        it.value.entries.forEach { signedItem ->
                            put(
                                signedItem.value.elementIdentifier,
                                signedItem.value.elementValue.toJsonElement(),
                            )
                        }
                    }
                })
                credential.issuerSigned.namespaces?.forEach {
                    put(it.key, buildJsonObject {
                        it.value.entries.forEach { signedItem ->
                            put(
                                signedItem.value.elementIdentifier,
                                signedItem.value.elementValue.toJsonElement()
                            )
                        }
                    })
                }
            }
        }
    }
}

private fun ElementValue.toJsonElement(): JsonElement {
    return this.boolean?.let { JsonPrimitive(it) }
        ?: this.string?.let { JsonPrimitive(it) }
        ?: this.bytes?.let {
            buildJsonArray {
                it.forEach {
                    this.add(JsonPrimitive(it.toInt()))
                }
            }
        } ?: this.drivingPrivilege?.let { drivingPriviledgeArray ->
            buildJsonArray {
                drivingPriviledgeArray.forEach { drivingPriviledge ->
                    this.add(
                        jsonSerializer.encodeToJsonElement(
                            drivingPriviledge
                        )
                    )
                }
            }
        } ?: this.date?.let {
            JsonPrimitive(it.toString())
        } ?: JsonNull
}

open class PresentationException(message: String) : Exception(message)

class CredentialRetrievalException :
    PresentationException("Credentials could not be retrieved from the store")

class MissingInputDescriptorMatchException(
    val inputDescriptor: InputDescriptor,
) : PresentationException("No match was found for input descriptor $inputDescriptor")

class CredentialPresentationException(
    val inputDescriptor: InputDescriptor,
    val credential: SubjectCredentialStore.StoreEntry,
    val candidateInputMatch: InputEvaluator.CandidateInputMatch,
) : PresentationException("Presentation of $inputDescriptor failed with credential $credential and matching $candidateInputMatch")