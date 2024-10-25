package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.catching
import at.asitplus.dif.*
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import at.asitplus.wallet.lib.data.dif.InputEvaluator
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionValidator
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier


/**
 * An agent that only implements [Holder], i.e. it can receive credentials form other agents
 * and present credentials to other agents.
 */
class HolderAgent(
    private val validator: Validator = Validator(),
    private val subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore(),
    private val jwsService: JwsService,
    private val coseService: CoseService,
    override val keyPair: KeyMaterial,
    private val verifiablePresentationFactory: VerifiablePresentationFactory = VerifiablePresentationFactory(
        jwsService = jwsService,
        coseService = coseService,
        identifier = keyPair.identifier,
    ),
    private val difInputEvaluator: InputEvaluator = InputEvaluator(),
) : Holder {

    constructor(
        keyMaterial: KeyMaterial,
        subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore()
    ) : this(
        validator = Validator(),
        subjectCredentialStore = subjectCredentialStore,
        jwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
        coseService = DefaultCoseService(DefaultCryptoService(keyMaterial)),
        keyPair = keyMaterial
    )

    /**
     * Sets the revocation list ot use for further processing of Verifiable Credentials
     *
     * @return `true` if the revocation list has been validated and set, `false` otherwise
     */
    override fun setRevocationList(it: String): Boolean {
        return validator.setRevocationList(it)
    }

    /**
     * Stores the verifiable credential in [credential] if it parses and validates,
     * and returns it for future reference.
     *
     * Note: Revocation credentials should not be stored, but set with [setRevocationList].
     */
    override suspend fun storeCredential(credential: Holder.StoreCredentialInput) = catching {
        when (credential) {
            is Holder.StoreCredentialInput.Vc -> {
                val vc = validator.verifyVcJws(credential.vcJws, keyPair.publicKey)
                if (vc !is Verifier.VerifyCredentialResult.SuccessJwt) {
                    throw VerificationError(vc.toString())
                }
                subjectCredentialStore.storeCredential(
                    vc.jws,
                    credential.vcJws,
                    credential.scheme,
                ).toStoredCredential()
            }

            is Holder.StoreCredentialInput.SdJwt -> {
                val sdJwt = validator.verifySdJwt(credential.vcSdJwt, keyPair.publicKey)
                if (sdJwt !is Verifier.VerifyCredentialResult.SuccessSdJwt) {
                    throw VerificationError(sdJwt.toString())
                }
                subjectCredentialStore.storeCredential(
                    sdJwt.sdJwt,
                    credential.vcSdJwt,
                    sdJwt.disclosures,
                    credential.scheme,
                ).toStoredCredential()
            }

            is Holder.StoreCredentialInput.Iso -> {
                val issuerKey: CoseKey? =
                    credential.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.let {
                        runCatching { X509Certificate.decodeFromDer(it) }.getOrNull()?.publicKey?.toCoseKey()
                            ?.getOrNull()
                    }
                val iso = validator.verifyIsoCred(credential.issuerSigned, issuerKey)
                if (iso !is Verifier.VerifyCredentialResult.SuccessIso) {
                    throw VerificationError(iso.toString())
                }
                subjectCredentialStore.storeCredential(iso.issuerSigned, credential.scheme)
                    .toStoredCredential()
            }
        }
    }


    /**
     * Gets a list of all stored credentials, with a revocation status.
     *
     * Note that the revocation status may be [Validator.RevocationStatus.UNKNOWN] if no revocation list
     * has been set with [setRevocationList]
     */
    override suspend fun getCredentials(): Collection<Holder.StoredCredential>? {
        val credentials = subjectCredentialStore.getCredentials().getOrNull()
            ?: return null.also { Napier.w("Got no credentials from subjectCredentialStore") }
        return credentials.map { it.toStoredCredential() }
    }

    private fun SubjectCredentialStore.StoreEntry.toStoredCredential() = when (this) {
        is SubjectCredentialStore.StoreEntry.Iso -> Holder.StoredCredential.Iso(
            this, Validator.RevocationStatus.UNKNOWN
        )

        is SubjectCredentialStore.StoreEntry.Vc -> Holder.StoredCredential.Vc(
            this, validator.checkRevocationStatus(vc)
        )

        is SubjectCredentialStore.StoreEntry.SdJwt -> Holder.StoredCredential.SdJwt(
            this, validator.checkRevocationStatus(sdJwt)
        )
    }

    /**
     * Gets a list of all valid stored credentials sorted by preference
     */
    private suspend fun getValidCredentialsByPriority() = getCredentials()
        ?.filter { it.status != Validator.RevocationStatus.REVOKED }
        ?.map { it.storeEntry }
        ?.sortedBy {
            // prefer iso credentials and sd jwt credentials over plain vc credentials
            // -> they support selective disclosure!
            when (it) {
                is SubjectCredentialStore.StoreEntry.Vc -> 2
                is SubjectCredentialStore.StoreEntry.SdJwt -> 1
                is SubjectCredentialStore.StoreEntry.Iso -> 1
            }
        }


    override suspend fun createPresentation(
        challenge: String,
        audienceId: String,
        presentationDefinition: PresentationDefinition,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: PathAuthorizationValidator?,
    ): KmmResult<Holder.PresentationResponseParameters> = runCatching {
        val submittedCredentials = matchInputDescriptorsAgainstCredentialStore(
            inputDescriptors = presentationDefinition.inputDescriptors,
            fallbackFormatHolder = fallbackFormatHolder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        ).getOrThrow().toDefaultSubmission()

        val validator = PresentationSubmissionValidator.createInstance(
            submissionRequirements = presentationDefinition.submissionRequirements,
            inputDescriptors = presentationDefinition.inputDescriptors,
        ).getOrThrow()

        if (!validator.isValidSubmission(submittedCredentials.keys)) {
            val missingInputDescriptors = presentationDefinition.inputDescriptors
                .map { it.id }.toSet() - submittedCredentials.keys

            throw PresentationException(
                "Submission requirements are unsatisfied: No credentials were submitted for input descriptors: $missingInputDescriptors"
            )
        }

        createPresentation(
            challenge = challenge,
            audienceId = audienceId,
            presentationDefinitionId = presentationDefinition.id,
            presentationSubmissionSelection = submittedCredentials,
        ).getOrThrow()
    }.wrap()

    override suspend fun createPresentation(
        challenge: String,
        audienceId: String,
        presentationDefinitionId: String?,
        presentationSubmissionSelection: Map<String, CredentialSubmission>,
    ): KmmResult<Holder.PresentationResponseParameters> = runCatching {
        val submissionList = presentationSubmissionSelection.toList()
        val presentationSubmission = PresentationSubmission.fromMatches(
            presentationId = presentationDefinitionId,
            matches = submissionList,
        )

        val verifiablePresentations = submissionList.map { match ->
            val credential = match.second.credential
            val disclosedAttributes = match.second.disclosedAttributes
            verifiablePresentationFactory.createVerifiablePresentation(
                challenge = challenge,
                audienceId = audienceId,
                credential = credential,
                disclosedAttributes = disclosedAttributes,
            ).getOrThrow()
        }

        Holder.PresentationResponseParameters(
            presentationSubmission = presentationSubmission,
            presentationResults = verifiablePresentations,
        )
    }.wrap()

    suspend fun createVcPresentation(
        validCredentials: List<String>,
        challenge: String,
        audienceId: String,
    ): KmmResult<Holder.CreatePresentationResult> = runCatching {
        verifiablePresentationFactory.createVcPresentation(
            validCredentials = validCredentials,
            challenge = challenge,
            audienceId = audienceId,
        )
    }.wrap()


    override suspend fun matchInputDescriptorsAgainstCredentialStore(
        inputDescriptors: Collection<InputDescriptor>,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: PathAuthorizationValidator?,
    ) = runCatching {
        findInputDescriptorMatches(
            inputDescriptors = inputDescriptors,
            credentials = getValidCredentialsByPriority()
                ?: throw PresentationException("Credentials could not be retrieved from the store"),
            fallbackFormatHolder = fallbackFormatHolder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        )
    }.wrap()

    private fun findInputDescriptorMatches(
        inputDescriptors: Collection<InputDescriptor>,
        credentials: Collection<SubjectCredentialStore.StoreEntry>,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: PathAuthorizationValidator?,
    ) = inputDescriptors.associateWith { inputDescriptor ->
        credentials.mapNotNull { credential ->
            evaluateInputDescriptorAgainstCredential(
                inputDescriptor = inputDescriptor,
                credential = credential,
                fallbackFormatHolder = fallbackFormatHolder,
                pathAuthorizationValidator = {
                    pathAuthorizationValidator?.invoke(credential, it) ?: true
                },
            ).getOrNull()?.let {
                credential to it
            }
        }.toMap()
    }.mapKeys {
        it.key.id
    }

    override fun evaluateInputDescriptorAgainstCredential(
        inputDescriptor: InputDescriptor,
        credential: SubjectCredentialStore.StoreEntry,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ) = catching {
        listOf(credential).filter {
            it.isFormatSupported(inputDescriptor.format ?: fallbackFormatHolder)
        }.filter {
            // iso credentials now have their doctype encoded into the id
            when (it) {
                is SubjectCredentialStore.StoreEntry.Iso -> it.scheme.isoDocType == inputDescriptor.id
                else -> true
            }
        }.firstNotNullOf {
            difInputEvaluator.evaluateConstraintFieldMatches(
                inputDescriptor = inputDescriptor,
                credential = CredentialToJsonConverter.toJsonElement(it),
                pathAuthorizationValidator = pathAuthorizationValidator,
            ).getOrThrow()
        }
    }

    /** assume credential format to be supported by the verifier if no format holder is specified */
    private fun SubjectCredentialStore.StoreEntry.isFormatSupported(supportedFormats: FormatHolder?): Boolean =
        supportedFormats?.let { formatHolder ->
            when (this) {
                is SubjectCredentialStore.StoreEntry.Vc -> formatHolder.jwtVp != null
                is SubjectCredentialStore.StoreEntry.SdJwt -> formatHolder.jwtSd != null
                is SubjectCredentialStore.StoreEntry.Iso -> formatHolder.msoMdoc != null
            }
        } ?: true

    private fun PresentationSubmission.Companion.fromMatches(
        presentationId: String?,
        matches: List<Pair<String, CredentialSubmission>>,
    ) = PresentationSubmission(
        id = uuid4().toString(),
        definitionId = presentationId,
        descriptorMap = matches.mapIndexed { index, match ->
            PresentationSubmissionDescriptor.fromMatch(
                inputDescriptorId = match.first,
                credential = match.second.credential,
                index = if (matches.size == 1) null else index,
            )
        },
    )

    private fun PresentationSubmissionDescriptor.Companion.fromMatch(
        credential: SubjectCredentialStore.StoreEntry,
        inputDescriptorId: String,
        index: Int?,
    ) = PresentationSubmissionDescriptor(
        id = inputDescriptorId,
        format = when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> ClaimFormatEnum.JWT_VP
            is SubjectCredentialStore.StoreEntry.SdJwt -> ClaimFormatEnum.JWT_SD
            is SubjectCredentialStore.StoreEntry.Iso -> ClaimFormatEnum.MSO_MDOC
        },
        // from https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1-2.4
        // These objects contain a field called path, which, for this specification,
        // MUST have the value $ (top level root path) when only one Verifiable Presentation is contained in the VP Token,
        // and MUST have the value $[n] (indexed path from root) when there are multiple Verifiable Presentations,
        // where n is the index to select.
        path = index?.let { "\$[$it]" } ?: "\$",
    )
}
