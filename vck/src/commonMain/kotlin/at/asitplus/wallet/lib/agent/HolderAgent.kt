package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.ClaimFormat
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationSubmission
import at.asitplus.dif.PresentationSubmissionDescriptor
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryResult
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.dif.PresentationExchangeInputEvaluator
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionValidator
import at.asitplus.wallet.lib.extensions.toDefaultSubmission
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.joinAll

/**
 * An agent that only implements [Holder], i.e. it can receive credentials from other agents
 * and present credentials to other agents.
 */
class HolderAgent(
    override val keyMaterial: KeyMaterial,
    private val subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore(),
    private val validator: Validator = Validator(),
    private val validatorVcJws: ValidatorVcJws = ValidatorVcJws(validator = validator),
    private val validatorSdJwt: ValidatorSdJwt = ValidatorSdJwt(validator = validator),
    private val validatorMdoc: ValidatorMdoc = ValidatorMdoc(validator = validator),
    private val signVerifiablePresentation: SignJwtFun<VerifiablePresentationJws> =
        SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    private val signKeyBinding: SignJwtFun<KeyBindingJws> = SignJwt(keyMaterial, JwsHeaderNone()),
    private val verifiablePresentationFactory: VerifiablePresentationFactory =
        VerifiablePresentationFactory(keyMaterial, signVerifiablePresentation, signKeyBinding),
    private val difInputEvaluator: PresentationExchangeInputEvaluator = PresentationExchangeInputEvaluator,
) : Holder {

    /**
     * Stores the verifiable credential in [credential] if it parses and validates,
     * and returns it for future reference.
     */
    override suspend fun storeCredential(credential: Holder.StoreCredentialInput) = catching {
        when (credential) {
            is Holder.StoreCredentialInput.Vc -> {
                val validated = validatorVcJws.verifyVcJws(credential.signedVcJws, keyMaterial.publicKey)
                if (validated !is Verifier.VerifyCredentialResult.SuccessJwt) {
                    val error = (validated as? Verifier.VerifyCredentialResult.ValidationError)?.cause
                        ?: Throwable("Invalid VC JWS")
                    throw VerificationError(error)
                }
                subjectCredentialStore.storeCredential(
                    validated.jws,
                    credential.vcJws,
                    credential.scheme,
                )
            }

            is Holder.StoreCredentialInput.SdJwt -> {
                val validated = validatorSdJwt.verifySdJwt(credential.signedSdJwtVc, keyMaterial.publicKey)
                if (validated !is Verifier.VerifyCredentialResult.SuccessSdJwt) {
                    val error = (validated as? Verifier.VerifyCredentialResult.ValidationError)?.cause
                        ?: Throwable("Invalid SD-JWT")
                    throw VerificationError(error)
                }
                subjectCredentialStore.storeCredential(
                    validated.verifiableCredentialSdJwt,
                    credential.vcSdJwt,
                    validated.disclosures,
                    credential.scheme,
                )
            }

            is Holder.StoreCredentialInput.Iso -> {
                val issuerKey: CoseKey? =
                    credential.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.firstOrNull()?.let {
                        runCatching { X509Certificate.decodeFromDer(it) }.getOrNull()?.decodedPublicKey?.getOrNull()
                            ?.toCoseKey()
                            ?.getOrNull()
                    }
                val validated = validatorMdoc.verifyIsoCred(credential.issuerSigned, issuerKey)
                if (validated !is Verifier.VerifyCredentialResult.SuccessIso) {
                    val error = (validated as? Verifier.VerifyCredentialResult.ValidationError)?.cause
                        ?: Throwable("Invalid ISO MDOC")
                    throw VerificationError(error)
                }
                subjectCredentialStore.storeCredential(validated.issuerSigned, credential.scheme)
            }
        }
    }


    /**
     * Gets a list of all stored credentials, with a revocation status.
     */
    override suspend fun getCredentials(): Collection<StoreEntry>? =
        subjectCredentialStore.getCredentials().getOrNull()

    /**
     * Gets a list of all valid stored credentials sorted by preference, possibly filtered by
     * [filterById]
     */
    private suspend fun getValidCredentialsByPriority(filterById: String? = null): List<StoreEntry>? {
        val availableCredentials = getCredentials() ?: return null

        val presortedCredentials = availableCredentials.filter {
            filterById == null || it.getDcApiId() == filterById
        }.sortedBy {
            // prefer iso credentials and sd jwt credentials over plain vc credentials
            // -> they support selective disclosure!
            when (it) {
                is StoreEntry.Vc -> 2
                is StoreEntry.SdJwt -> 1
                is StoreEntry.Iso -> 1
            }
        }

        val withRevocationStatusQueryIssued = presortedCredentials.map {
            it to coroutineScope {
                async {
                    validator.checkCredentialFreshness(it)
                }
            }
        }
        withRevocationStatusQueryIssued.map {
            it.second
        }.joinAll()
        val withRevocationStatusAvailable = withRevocationStatusQueryIssued.map {
            it.first to it.second.await()
        }
        return withRevocationStatusAvailable.sortedBy {
            if (it.second.isFresh) {
                0
            } else {
                1
            }
        }.map {
            it.first
        }
    }

    override suspend fun createDefaultPresentation(
        request: PresentationRequestParameters,
        credentialPresentationRequest: CredentialPresentationRequest,
    ): KmmResult<PresentationResponseParameters> = when (credentialPresentationRequest) {
        is CredentialPresentationRequest.PresentationExchangeRequest -> createPresentation(
            request = request,
            credentialPresentation = credentialPresentationRequest.toCredentialPresentation(),
        )

        is CredentialPresentationRequest.DCQLRequest -> createPresentation(
            request = request,
            credentialPresentation = credentialPresentationRequest.toCredentialPresentation(),
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

    override suspend fun matchInputDescriptorsAgainstCredentialStore(
        inputDescriptors: Collection<InputDescriptor>,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: PathAuthorizationValidator?,
        filterById: String?,
    ) = catching {
        findInputDescriptorMatches(
            inputDescriptors = inputDescriptors,
            credentials = getValidCredentialsByPriority(filterById = filterById)
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

    override suspend fun matchDCQLQueryAgainstCredentialStore(
        dcqlQuery: DCQLQuery,
        filterById: String?,
    ): KmmResult<DCQLQueryResult<StoreEntry>> {
        return DCQLQueryAdapter(dcqlQuery).select(
            credentials = getValidCredentialsByPriority(filterById)
                ?: throw PresentationException("Credentials could not be retrieved from the store"),
        )
    }

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

    private fun StoreEntry.toFormat(): ClaimFormat = when (this) {
        is StoreEntry.Vc -> ClaimFormat.JWT_VP
        is StoreEntry.SdJwt -> ClaimFormat.SD_JWT
        is StoreEntry.Iso -> ClaimFormat.MSO_MDOC
    }

    private fun CredentialPresentationRequest.PresentationExchangeRequest.validateSubmission(
        credentialSubmissions: Map<String, PresentationExchangeCredentialDisclosure>,
    ) = catching {
        val validator = PresentationSubmissionValidator.createInstance(presentationDefinition).getOrThrow()
        require(validator.isValidSubmission(credentialSubmissions.keys)) {
            "Submission requirements are not satisfied"
        }

        // making sure, that all the submissions actually match the corresponding input descriptor requirements
        credentialSubmissions.forEach { submission ->
            val inputDescriptor = presentationDefinition.inputDescriptors
                .firstOrNull { it.id == submission.key }
                ?: throw IllegalArgumentException("Invalid input descriptor id: ${submission.key}")

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
                disclosedAttributes.firstOrNull { allowedPaths.contains(it) }
                    ?: throw IllegalArgumentException(inputDescriptor.errorMessage(constraintField))
            }
            // TODO: maybe we also want to validate, whether there are any redundant disclosed attributes?
            //  this would be the case if there is only one constraint field with path "$['name']", but two attributes are disclosed
        }
    }

    private fun InputDescriptor.errorMessage(field: Map.Entry<ConstraintField, NodeList>): String =
        "Input descriptor constraints are not satisfied: ${details(field)}"

    private fun InputDescriptor.details(field: Map.Entry<ConstraintField, NodeList>): String =
        "${id}.${field.key.id?.let { " Missing field: $it" }}"

}
