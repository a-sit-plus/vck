package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.ClaimFormat
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.dif.PresentationSubmission
import at.asitplus.dif.PresentationSubmissionDescriptor
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryResult
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import at.asitplus.wallet.lib.data.dif.PresentationExchangeInputEvaluator
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionValidator
import at.asitplus.wallet.lib.data.third_party.at.asitplus.oidc.dcql.toDefaultSubmission
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
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
    private val verifiablePresentationFactory: VerifiablePresentationFactory =
        VerifiablePresentationFactory(jwsService, coseService, keyPair.identifier),
    private val difInputEvaluator: PresentationExchangeInputEvaluator = PresentationExchangeInputEvaluator,
) : Holder {

    constructor(
        keyMaterial: KeyMaterial,
        subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore(),
        validator: Validator = Validator(),
    ) : this(
        validator = validator,
        subjectCredentialStore = subjectCredentialStore,
        jwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
        coseService = DefaultCoseService(DefaultCryptoService(keyMaterial)),
        keyPair = keyMaterial
    )

    /**
     * Stores the verifiable credential in [credential] if it parses and validates,
     * and returns it for future reference.
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
                val sdJwt = validator.verifySdJwt(SdJwtSigned.parse(credential.vcSdJwt)!!, keyPair.publicKey)
                if (sdJwt !is Verifier.VerifyCredentialResult.SuccessSdJwt) {
                    throw VerificationError(sdJwt.toString())
                }
                subjectCredentialStore.storeCredential(
                    sdJwt.verifiableCredentialSdJwt,
                    credential.vcSdJwt,
                    sdJwt.disclosures,
                    credential.scheme,
                ).toStoredCredential()
            }

            is Holder.StoreCredentialInput.Iso -> {
                val issuerKey: CoseKey? =
                    credential.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.firstOrNull()?.let {
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
     */
    override suspend fun getCredentials(): Collection<Holder.StoredCredential>? {
        val credentials = subjectCredentialStore.getCredentials().getOrNull()
            ?: return null.also { Napier.w("Got no credentials from subjectCredentialStore") }
        return credentials.map { it.toStoredCredential() }
    }

    private suspend fun StoreEntry.toStoredCredential() = when (this) {
        is StoreEntry.Iso -> Holder.StoredCredential.Iso(
            this,
            validator.checkRevocationStatus(issuerSigned),
        )

        is StoreEntry.Vc -> Holder.StoredCredential.Vc(
            this, validator.checkRevocationStatus(vc)
        )

        is StoreEntry.SdJwt -> Holder.StoredCredential.SdJwt(
            this, validator.checkRevocationStatus(sdJwt)
        )
    }

    /**
     * Gets a list of all valid stored credentials sorted by preference
     */
    private suspend fun getValidCredentialsByPriority() = getCredentials()
        ?.filter { it.status?.isInvalid != true }
        ?.map { it.storeEntry }
        ?.sortedBy {
            // prefer iso credentials and sd jwt credentials over plain vc credentials
            // -> they support selective disclosure!
            when (it) {
                is StoreEntry.Vc -> 2
                is StoreEntry.SdJwt -> 1
                is StoreEntry.Iso -> 1
            }
        }

    override suspend fun createDefaultPresentation(
        request: PresentationRequestParameters,
        credentialPresentationRequest: CredentialPresentationRequest,
    ): KmmResult<PresentationResponseParameters> = when (credentialPresentationRequest) {
        is CredentialPresentationRequest.PresentationExchangeRequest -> createPresentation(
            request = request,
            credentialPresentation = credentialPresentationRequest.toCredentialPresentation()
        )

        is CredentialPresentationRequest.DCQLRequest -> createPresentation(
            request = request,
            credentialPresentation = credentialPresentationRequest.toCredentialPresentation()
        )
    }

    override suspend fun createPresentation(
        request: PresentationRequestParameters,
        credentialPresentation: CredentialPresentation,
    ): KmmResult<PresentationResponseParameters> = when (credentialPresentation) {
        is CredentialPresentation.DCQLPresentation -> createDCQLPresentation(
            request = request,
            credentialPresentation = credentialPresentation,
        )

        is CredentialPresentation.PresentationExchangePresentation -> createPresentationExchangePresentation(
            request = request,
            credentialPresentation = credentialPresentation
        )
    }

    private suspend fun createDefaultPresentationExchangePresentation(
        request: PresentationRequestParameters,
        presentationDefinition: PresentationDefinition,
        fallbackFormatHolder: FormatHolder?,
    ): KmmResult<PresentationResponseParameters.PresentationExchangeParameters> =
        createPresentationExchangePresentation(
            request = request,
            credentialPresentation = CredentialPresentation.PresentationExchangePresentation(
                CredentialPresentationRequest.PresentationExchangeRequest(
                    presentationDefinition,
                    fallbackFormatHolder,
                ),
            )
        )

    private suspend fun createPresentationExchangePresentation(
        request: PresentationRequestParameters,
        credentialPresentation: CredentialPresentation.PresentationExchangePresentation,
    ): KmmResult<PresentationResponseParameters.PresentationExchangeParameters> = catching {
        val presentationDefinition = credentialPresentation.presentationRequest.presentationDefinition

        val presentationCredentialSelection = credentialPresentation.inputDescriptorSubmissions
            ?: matchInputDescriptorsAgainstCredentialStore(
                inputDescriptors = presentationDefinition.inputDescriptors,
                fallbackFormatHolder = credentialPresentation.presentationRequest.fallbackFormatHolder,
            ).getOrThrow().toDefaultSubmission()

        credentialPresentation.presentationRequest.validateSubmission(presentationCredentialSelection)
            .onFailure { throw PresentationException(it) }

        val submissionList = presentationCredentialSelection.mapValues {
            PresentationExchangeCredentialDisclosure(
                credential = it.value.credential,
                disclosedAttributes = it.value.disclosedAttributes
            )
        }.toList()

        // Presentation will be one single ISO mDoc DeviceResponse, containing multiple documents
        val isSingleIsoMdocPresentation = submissionList.all { it.second.credential is StoreEntry.Iso }
        val presentationSubmission = PresentationSubmission.fromMatches(
            presentationId = presentationDefinition.id,
            matches = submissionList,
            isSingleIsoMdocPresentation = isSingleIsoMdocPresentation
        )

        val verifiablePresentations = if (isSingleIsoMdocPresentation) {
            listOf(
                verifiablePresentationFactory.createVerifiablePresentationForIsoCredentials(
                    request = request,
                    credentialAndDisclosedAttributes = submissionList
                        .associate { it.second.credential as StoreEntry.Iso to it.second.disclosedAttributes },
                ).getOrThrow()
            )
        } else {
            submissionList.map { match ->
                verifiablePresentationFactory.createVerifiablePresentation(
                    request = request,
                    credential = match.second.credential,
                    disclosedAttributes = match.second.disclosedAttributes,
                ).getOrThrow()
            }
        }

        PresentationResponseParameters.PresentationExchangeParameters(
            presentationSubmission = presentationSubmission,
            presentationResults = verifiablePresentations,
        )
    }

    private suspend fun createDCQLPresentation(
        request: PresentationRequestParameters,
        credentialPresentation: CredentialPresentation.DCQLPresentation,
    ): KmmResult<PresentationResponseParameters.DCQLParameters> = catching {
        val dcqlQuery = credentialPresentation.presentationRequest.dcqlQuery

        val requestedCredentialSetQueries =
            credentialPresentation.presentationRequest.dcqlQuery.requestedCredentialSetQueries
        val credentialSubmissions = credentialPresentation.credentialQuerySubmissions
            ?: matchDCQLQueryAgainstCredentialStore(dcqlQuery).getOrThrow()
                .toDefaultSubmission().getOrThrow()

        DCQLQuery.Procedures.isSatisfactoryCredentialSubmission(
            credentialSubmissions = credentialSubmissions.keys,
            requestedCredentialSetQueries = requestedCredentialSetQueries,
        ).let {
            if (!it) {
                throw IllegalArgumentException("Submission does not satisfy requested credential set queries.")
            }
        }

        val verifiablePresentations = credentialSubmissions.mapValues { match ->
            val credential = match.value.credential
            val disclosedAttributes = match.value.matchingResult
            verifiablePresentationFactory.createVerifiablePresentation(
                request = request,
                credential = credential,
                disclosedAttributes = disclosedAttributes,
            ).getOrThrow()
        }

        PresentationResponseParameters.DCQLParameters(
            verifiablePresentations = verifiablePresentations,
        )
    }

    suspend fun createVcPresentation(
        validCredentials: List<String>,
        request: PresentationRequestParameters,
    ): KmmResult<CreatePresentationResult> = catching {
        verifiablePresentationFactory.createVcPresentation(
            validCredentials = validCredentials,
            request = request,
        )
    }

    override suspend fun matchInputDescriptorsAgainstCredentialStore(
        inputDescriptors: Collection<InputDescriptor>,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: PathAuthorizationValidator?,
    ) = catching {
        findInputDescriptorMatches(
            inputDescriptors = inputDescriptors,
            credentials = getValidCredentialsByPriority()
                ?: throw PresentationException("Credentials could not be retrieved from the store"),
            fallbackFormatHolder = fallbackFormatHolder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        )
    }

    private fun findInputDescriptorMatches(
        inputDescriptors: Collection<InputDescriptor>,
        credentials: Collection<StoreEntry>,
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
            ).onFailure {
                Napier.d("findInputDescriptorMatches failed for credential with schemaUri ${credential.schemaUri}", it)
            }.getOrNull()?.let {
                credential to it
            }
        }.toMap()
    }.mapKeys {
        it.key.id
    }

    override fun evaluateInputDescriptorAgainstCredential(
        inputDescriptor: InputDescriptor,
        credential: StoreEntry,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ) = difInputEvaluator.evaluateInputDescriptorAgainstCredential(
        inputDescriptor = inputDescriptor,
        fallbackFormatHolder = fallbackFormatHolder,
        credentialClaimStructure = CredentialToJsonConverter.toJsonElement(credential),
        credentialFormat = when (credential) {
            is StoreEntry.Vc -> CredentialFormatEnum.JWT_VC
            is StoreEntry.SdJwt -> CredentialFormatEnum.DC_SD_JWT
            is StoreEntry.Iso -> CredentialFormatEnum.MSO_MDOC
        },
        credentialScheme = when (credential) {
            is StoreEntry.Vc -> credential.scheme?.vcType
            is StoreEntry.SdJwt -> credential.scheme?.sdJwtType
            is StoreEntry.Iso -> credential.scheme?.isoDocType
        },
        pathAuthorizationValidator = pathAuthorizationValidator,
    )

    override suspend fun matchDCQLQueryAgainstCredentialStore(dcqlQuery: DCQLQuery): KmmResult<DCQLQueryResult<StoreEntry>> {
        return DCQLQueryAdapter(dcqlQuery).select(
            credentials = getValidCredentialsByPriority()
                ?: throw PresentationException("Credentials could not be retrieved from the store"),
        )
    }

    /** assume credential format to be supported by the verifier if no format holder is specified */
    @Suppress("DEPRECATION")
    private fun StoreEntry.isFormatSupported(supportedFormats: FormatHolder?): Boolean =
        supportedFormats?.let { formatHolder ->
            when (this) {
                is StoreEntry.Vc -> formatHolder.jwtVp != null
                is StoreEntry.SdJwt -> formatHolder.jwtSd != null || formatHolder.sdJwt != null
                is StoreEntry.Iso -> formatHolder.msoMdoc != null
            }
        } ?: true

    private fun PresentationSubmission.Companion.fromMatches(
        presentationId: String?,
        matches: List<Pair<String, PresentationExchangeCredentialDisclosure>>,
        isSingleIsoMdocPresentation: Boolean,
    ) = PresentationSubmission(
        id = uuid4().toString(),
        definitionId = presentationId,
        descriptorMap = matches.mapIndexed { index, match ->
            PresentationSubmissionDescriptor.fromMatch(
                inputDescriptorId = match.first,
                credential = match.second.credential,
                index = if (matches.size == 1 || isSingleIsoMdocPresentation) null else index,
            )
        },
    )

    private fun PresentationSubmissionDescriptor.Companion.fromMatch(
        credential: StoreEntry,
        inputDescriptorId: String,
        index: Int?,
    ) = PresentationSubmissionDescriptor(
        id = inputDescriptorId,
        format = credential.toFormat(),
        // from https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1-2.4
        // These objects contain a field called path, which, for this specification,
        // MUST have the value $ (top level root path) when only one Verifiable Presentation is contained in the VP Token,
        // and MUST have the value $[n] (indexed path from root) when there are multiple Verifiable Presentations,
        // where n is the index to select.
        path = index?.let { "\$[$it]" } ?: "\$",
    )

    @Suppress("DEPRECATION")
    private fun StoreEntry.toFormat(): ClaimFormat = when (this) {
        is StoreEntry.Vc -> ClaimFormat.JWT_VP
        // TODO In 5.4.0, use SD_JWT instead of JWT_SD
        is StoreEntry.SdJwt -> ClaimFormat.JWT_SD
        is StoreEntry.Iso -> ClaimFormat.MSO_MDOC
    }


    private fun CredentialPresentationRequest.PresentationExchangeRequest.validateSubmission(
        credentialSubmissions: Map<String, PresentationExchangeCredentialDisclosure>,
    ) = catching {
        val validator = PresentationSubmissionValidator.createInstance(presentationDefinition).getOrThrow()
        if (!validator.isValidSubmission(credentialSubmissions.keys)) {
            Napier.w("submission requirements are not satisfied")
            throw IllegalArgumentException("Submission requirements are not satisfied")
        }

        // making sure, that all the submissions actually match the corresponding input descriptor requirements
        credentialSubmissions.forEach { submission ->
            val inputDescriptor = presentationDefinition.inputDescriptors.firstOrNull {
                it.id == submission.key
            } ?: run {
                Napier.w("Invalid input descriptor id")
                throw IllegalArgumentException("Invalid input descriptor id")
            }

            val constraintFieldMatches = evaluateInputDescriptorAgainstCredential(
                inputDescriptor = inputDescriptor,
                credential = submission.value.credential,
                fallbackFormatHolder = fallbackFormatHolder,
                pathAuthorizationValidator = { true },
            ).getOrThrow()

            val disclosedAttributes = submission.value.disclosedAttributes.map { it.toString() }

            // find a matching path for each constraint field
            constraintFieldMatches.filter {
                // only need to validate non-optional constraint fields
                it.key.optional != true
            }.forEach { constraintField ->
                val allowedPaths = constraintField.value.map {
                    it.normalizedJsonPath.toString()
                }
                disclosedAttributes.firstOrNull { allowedPaths.contains(it) } ?: run {
                    val keyId = constraintField.key.id?.let { " Missing field: $it" }
                    Napier.w("Input descriptor constraints are not satisfied: ${inputDescriptor.id}.$keyId")
                    throw IllegalArgumentException("Input descriptor constraints are not satisfied: ${inputDescriptor.id}.$keyId")
                }
            }
            // TODO: maybe we also want to validate, whether there are any redundant disclosed attributes?
            //  this would be the case if there is only one constraint field with path "$['name']", but two attributes are disclosed
        }
    }
}
