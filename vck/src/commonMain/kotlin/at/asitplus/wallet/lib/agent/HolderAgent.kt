package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationSubmission
import at.asitplus.dif.PresentationSubmissionDescriptor
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.openid.dcql.DCQLQuery
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
    override suspend fun storeCredential(
        credential: Holder.StoreCredentialInput,
        renewalInfo: CredentialRenewalInfo?
    ) = catching {
        when (credential) {
            is Holder.StoreCredentialInput.Vc -> {
                val validated = validatorVcJws.verifyVcJws(credential.signedVcJws, keyMaterial.publicKey).getOrThrow()
                subjectCredentialStore.storeCredential(
                    vc = validated.jws,
                    vcSerialized = credential.vcJws,
                    scheme = credential.scheme,
                    renewalInfo = renewalInfo
                )
            }

            is Holder.StoreCredentialInput.SdJwt -> {
                if (credential.signedSdJwtVc.keyBindingJws != null) {
                    throw Throwable("Issued SD-JWT credentials must not contain a KB")
                }
                val validated = validatorSdJwt.verifySdJwt(credential.signedSdJwtVc, keyMaterial.publicKey).getOrThrow()
                subjectCredentialStore.storeCredential(
                    vc = validated.verifiableCredentialSdJwt,
                    vcSerialized = credential.vcSdJwt,
                    disclosures = validated.disclosures,
                    scheme = credential.scheme,
                    renewalInfo = renewalInfo
                )
            }

            is Holder.StoreCredentialInput.Iso -> {
                val validated = validatorMdoc.verifyIsoCred(credential.issuerSigned, credential.extractIssuerKey()).getOrThrow()
                subjectCredentialStore.storeCredential(
                    issuerSigned = validated.issuerSigned,
                    scheme = credential.scheme,
                    renewalInfo = renewalInfo
                )
            }
        }
    }

    private fun Holder.StoreCredentialInput.Iso.extractIssuerKey(): CoseKey? =
        issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.firstOrNull()?.let {
            catchingUnwrapped { X509Certificate.decodeFromDer(it) }.getOrNull()?.decodedPublicKey?.getOrNull()
                ?.toCoseKey()
                ?.getOrNull()
        }


    /**
     * Gets a list of all stored credentials, with a revocation status.
     */
    override suspend fun getCredentials(): Collection<StoreEntry>? =
        subjectCredentialStore.getCredentials().getOrNull()

    /** Gets a list of all valid stored credentials sorted by preference, possibly filtered by [filterByIds]. */
    private suspend fun getValidCredentialsByPriority(filterByIds: Collection<String>? = null): List<StoreEntry>? {
        val availableCredentials = getCredentials() ?: return null

        val presortedCredentials = availableCredentials
            .filter { filterByIds == null || filterByIds.contains(it.getDcApiId()) }
            .sortedBy { it.sortKey() }

        val withRevocationStatusQueryIssued = presortedCredentials.map {
            it to coroutineScope {
                async {
                    validator.checkCredentialFreshness(it)
                }
            }
        }
        withRevocationStatusQueryIssued.map { it.second }.joinAll()
        val withRevocationStatusAvailable = withRevocationStatusQueryIssued.map {
            it.first to it.second.await()
        }
        return withRevocationStatusAvailable.sortedBy {
            if (it.second.isFresh) 0 else 1
        }.map { it.first }
    }

    /** Prefer credentials with support for selective disclosure. */
    private fun StoreEntry.sortKey(): Int = when (this) {
        is StoreEntry.Vc -> 2
        is StoreEntry.SdJwt -> 1
        is StoreEntry.Iso -> 1
    }

    override suspend fun createDefaultPresentation(
        request: PresentationRequestParameters,
        credentialPresentationRequest: CredentialPresentationRequest,
    ): KmmResult<PresentationResponseParameters> =
        createPresentation(request, credentialPresentationRequest.toCredentialPresentation())

    override suspend fun createPresentation(
        request: PresentationRequestParameters,
        credentialPresentation: CredentialPresentation,
    ): KmmResult<PresentationResponseParameters> = when (credentialPresentation) {
        is CredentialPresentation.DCQLPresentation ->
            createDCQLPresentation(request, credentialPresentation)

        is CredentialPresentation.PresentationExchangePresentation ->
            createPresentationExchangePresentation(request, credentialPresentation)
    }

    private suspend fun createPresentationExchangePresentation(
        request: PresentationRequestParameters,
        credentialPresentation: CredentialPresentation.PresentationExchangePresentation,
    ): KmmResult<PresentationResponseParameters.PresentationExchangeParameters> = catching {
        val presentationDefinition = credentialPresentation.presentationRequest.presentationDefinition

        val presentationCredentialSelection = credentialPresentation.inputDescriptorSubmissions
            ?: matchInputDescriptorsAgainstCredentialStoreV2(
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

        if (request.returnOneDeviceResponse) {
            PresentationResponseParameters.PresentationExchangeParameters(
                presentationSubmission = PresentationSubmission.fromMatches(
                    presentationId = presentationDefinition.id,
                    matches = submissionList,
                    isSingleIsoMdocPresentation = true
                ),
                presentationResults = listOf(
                    verifiablePresentationFactory.createVerifiablePresentation(
                        request = request,
                        credentialAndDisclosedAttributes = submissionList
                            .associate { it.second.credential as StoreEntry.Iso to it.second.disclosedAttributes },
                    ).getOrThrow()
                )
            )
        } else {
            PresentationResponseParameters.PresentationExchangeParameters(
                presentationSubmission = PresentationSubmission.fromMatches(
                    presentationId = presentationDefinition.id,
                    matches = submissionList
                ),
                presentationResults = submissionList.map { match ->
                    verifiablePresentationFactory.createVerifiablePresentation(
                        request = request,
                        credential = match.second.credential,
                        disclosedAttributes = match.second.disclosedAttributes,
                    ).getOrThrow()
                },
            )
        }
    }

    private suspend fun createDCQLPresentation(
        request: PresentationRequestParameters,
        credentialPresentation: CredentialPresentation.DCQLPresentation,
    ): KmmResult<PresentationResponseParameters.DCQLParameters> = catching {
        val dcqlQuery = credentialPresentation.presentationRequest.dcqlQuery

        val requestedCredentialSetQueries =
            credentialPresentation.presentationRequest.dcqlQuery.requestedCredentialSetQueries
        val credentialSubmissions = credentialPresentation.credentialQuerySubmissions
            ?: matchDCQLQueryAgainstCredentialStoreV2(dcqlQuery).getOrThrow()
                .toDefaultSubmission(dcqlQuery).getOrThrow()

        DCQLQuery.Procedures.isSatisfactoryCredentialSubmission(
            credentialSubmissions = credentialSubmissions.keys,
            requestedCredentialSetQueries = requestedCredentialSetQueries,
        ).let {
            if (!it) {
                throw IllegalArgumentException("Submission does not satisfy requested credential set queries.")
            }
        }

        val verifiablePresentations = credentialSubmissions.mapValues { (queryId, submissions) ->
            val query = credentialPresentation.presentationRequest.dcqlQuery.credentials.first {
                it.id == queryId
            }
            if(query.multiple != true && submissions.size != 1) {
                throw IllegalArgumentException("Credential query ${query.id} does not allow multiple submission, but ${submissions.size} were provided.")
            }
            submissions.map {
                val credential = it.credential
                if(credential is StoreEntry.Vc && !query.requireCryptographicHolderBinding) {
                    if(it.matchingResult !is DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult) {
                        throw IllegalArgumentException("Credential type only allows disclosure of all attributes.")
                    }
                    CreatePresentationResult.VcJws(credential.vcSerialized)
                } else {
                    verifiablePresentationFactory.createVerifiablePresentation(
                        request = request,
                        credential = credential,
                        disclosedAttributes = it.matchingResult,
                    ).getOrThrow()
                }
            }
        }

        PresentationResponseParameters.DCQLParameters(verifiablePresentations)
    }

    override suspend fun matchInputDescriptorsAgainstCredentialStoreV2(
        inputDescriptors: Collection<InputDescriptor>,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: PathAuthorizationValidator?,
        filterByIds: Collection<String>?,
    ) = catching {
        findInputDescriptorMatches(
            inputDescriptors = inputDescriptors,
            credentials = getValidCredentialsByPriority(filterByIds = filterByIds)
                ?: throw PresentationException("Credentials could not be retrieved from the store"),
            fallbackFormatHolder = fallbackFormatHolder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        )
    }

    private fun findInputDescriptorMatches(
        inputDescriptors: Collection<InputDescriptor>,
        credentials: List<StoreEntry>,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: PathAuthorizationValidator?,
    ) = HolderPresentationExchangeQueryMatchingResult(
        credentials = credentials,
        queryMatchingResult = PresentationExchangeQueryMatchingResult(
            inputDescriptors.associateWith { inputDescriptor ->
                credentials.map { credential ->
                    evaluateInputDescriptorAgainstCredential(
                        inputDescriptor = inputDescriptor,
                        credential = credential,
                        fallbackFormatHolder = fallbackFormatHolder,
                        pathAuthorizationValidator = {
                            pathAuthorizationValidator?.invoke(credential, it) ?: true
                        },
                    ).onFailure {
                        Napier.d(
                            "findInputDescriptorMatches failed for credential with schemaUri ${credential.schemaUri}",
                            it
                        )
                    }
                }
            }.mapKeys {
                it.key.id
            },
        )
    )

    override fun evaluateInputDescriptorAgainstCredential(
        inputDescriptor: InputDescriptor,
        credential: StoreEntry,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ) = difInputEvaluator.evaluateInputDescriptorAgainstCredential(
        inputDescriptor = inputDescriptor,
        fallbackFormatHolder = fallbackFormatHolder,
        credentialClaimStructure = CredentialToJsonConverter.toJsonElement(credential),
        credentialFormat = credential.credentialFormat,
        credentialScheme = credential.schemeIdentifier(),
        pathAuthorizationValidator = pathAuthorizationValidator,
    )

    private fun StoreEntry.schemeIdentifier(): String? = when (this) {
        is StoreEntry.Vc -> scheme?.vcType
        is StoreEntry.SdJwt -> scheme?.sdJwtType
        is StoreEntry.Iso -> scheme?.isoDocType
    }

    override suspend fun matchDCQLQueryAgainstCredentialStoreV2(
        dcqlQuery: DCQLQuery,
        filterByIds: Collection<String>?,
    ): KmmResult<HolderDCQLQueryMatchingResult<StoreEntry>> = catching {
        val credentials = getValidCredentialsByPriority(filterByIds)
            ?: throw PresentationException("Credentials could not be retrieved from the store")
        HolderDCQLQueryMatchingResult(
            dcqlQueryMatchingResult = DCQLQueryAdapter(dcqlQuery).select(
                credentials = credentials
            ),
            credentials = credentials,
        )
    }

    private fun PresentationSubmission.Companion.fromMatches(
        presentationId: String?,
        matches: List<Pair<String, PresentationExchangeCredentialDisclosure<StoreEntry>>>,
        isSingleIsoMdocPresentation: Boolean = false,
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
        format = credential.claimFormat,
        // from https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1-2.4
        // These objects contain a field called path, which, for this specification,
        // MUST have the value $ (top level root path) when only 1 Verifiable Presentation is contained in the VP Token,
        // and MUST have the value $[n] (indexed path from root) when there are multiple Verifiable Presentations,
        // where n is the index to select.
        path = index?.let { "\$[$it]" } ?: "\$",
    )

    private fun CredentialPresentationRequest.PresentationExchangeRequest.validateSubmission(
        credentialSubmissions: Map<String, PresentationExchangeCredentialDisclosure<StoreEntry>>,
    ) = catching {
        val validator = PresentationSubmissionValidator.createInstance(presentationDefinition).getOrThrow()
        require(validator.isValidSubmission(credentialSubmissions.keys)) { "Submission requirements are not satisfied" }

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
