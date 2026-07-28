@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationSubmission
import at.asitplus.dif.PresentationSubmissionDescriptor
import at.asitplus.iso.DeviceRequest
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.openid.dcql.DCQLIsoMdocZkCredentialQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.PresentationExchangeRequest
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import at.asitplus.wallet.lib.data.dif.PresentationExchangeInputEvaluator
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionValidator
import at.asitplus.wallet.lib.procedures.iso.DeviceRetrievalProcedure
import com.benasher44.uuid.uuid4

/** Resolves and validates holder submissions before creating their format-specific response artifacts. */
internal class PresentationResponseCreator(
    private val verifiablePresentationFactory: VerifiablePresentationFactory,
) {
    private val difInputEvaluator: PresentationExchangeInputEvaluator = PresentationExchangeInputEvaluator

    suspend fun create(
        request: PresentationRequestParameters,
        credentialPresentation: CredentialPresentation,
        matchDCQLQuery: suspend (DCQLQuery) -> KmmResult<HolderDCQLQueryMatchingResult<StoreEntry>>,
        matchDeviceRequest: suspend (DeviceRequest) -> KmmResult<HolderIsoDeviceRetrievalQueryMatchingResult<StoreEntry>>,
        matchPresentationExchange: suspend (PresentationExchangeRequest) -> KmmResult<HolderPresentationExchangeQueryMatchingResult<StoreEntry>>,
    ): KmmResult<PresentationResponseParameters> = catching {
        when (credentialPresentation) {
            is CredentialPresentation.DCQLPresentation ->
                createDcql(
                    request,
                    credentialPresentation,
                    matchDCQLQuery
                )

            is CredentialPresentation.PresentationExchangePresentation ->
                createPresentationExchange(
                    request,
                    credentialPresentation,
                    matchPresentationExchange
                )

            is CredentialPresentation.IsoDeviceRetrievalPresentation ->
                createDeviceResponse(
                    request,
                    credentialPresentation,
                    matchDeviceRequest
                )
        }
    }

    private suspend fun createDcql(
        request: PresentationRequestParameters,
        presentation: CredentialPresentation.DCQLPresentation,
        matchDCQLQuery: suspend (DCQLQuery) -> KmmResult<HolderDCQLQueryMatchingResult<StoreEntry>>,
    ): PresentationResponseParameters.DCQLParameters {
        val dcqlQuery = presentation.presentationRequest.dcqlQuery
        val credentialSubmissions = presentation.credentialQuerySubmissions
            ?: matchDCQLQuery(dcqlQuery).getOrThrow().toDefaultSubmission(dcqlQuery).getOrThrow()

        DCQLQuery.Procedures.checkCredentialSetQueryRequirements(
            credentialSubmissions = credentialSubmissions.keys,
            requestedCredentialSetQueries = dcqlQuery.requestedCredentialSetQueries,
        ).getOrThrow()

        val presentations = credentialSubmissions.mapValues { (queryId, submissions) ->
            val query = dcqlQuery.credentials.first { it.id == queryId }
            if (!query.multiple && submissions.size != 1) {
                throw IllegalArgumentException(
                    "Credential query ${query.id} does not allow multiple submission, but ${submissions.size} were provided."
                )
            }
            submissions.map {
                val credential = it.credential
                if (credential is StoreEntry.Vc && !query.requireCryptographicHolderBinding) {
                    if (it.matchingResult !is DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult) {
                        throw IllegalArgumentException("Credential type only allows disclosure of all attributes.")
                    }
                    CreatePresentationResult.VcJws(credential.vcSerialized)
                } else {
                    verifiablePresentationFactory.createVerifiablePresentation(
                        request = request,
                        credential = credential,
                        disclosedAttributes = it.matchingResult,
                        zkMetadata = when (query) {
                            is DCQLIsoMdocZkCredentialQuery -> ZkMetadata.IsoMdocZk(query.meta.zkSystemType)
                            else -> null
                        }
                    ).getOrThrow()
                }
            }
        }

        return PresentationResponseParameters.DCQLParameters(presentations)
    }

    private suspend fun createDeviceResponse(
        request: PresentationRequestParameters,
        presentation: CredentialPresentation.IsoDeviceRetrievalPresentation,
        matchDeviceRequest: suspend (DeviceRequest) -> KmmResult<HolderIsoDeviceRetrievalQueryMatchingResult<StoreEntry>>,
    ): PresentationResponseParameters.DeviceRetrievalParameters {
        val deviceRequest = presentation.presentationRequest.deviceRequest
        val submissions = presentation.submissions
            ?: matchDeviceRequest(deviceRequest).getOrThrow().toDefaultSubmission().getOrThrow()
        val selectedCredentials = DeviceRetrievalProcedure.validateSubmission(deviceRequest, submissions).getOrThrow()
        val result = verifiablePresentationFactory.createVerifiablePresentation(
            request = request,
            isoPresentationParameters = selectedCredentials,
        ).getOrThrow()
        return PresentationResponseParameters.DeviceRetrievalParameters(result.deviceResponse)
    }

    @Suppress("DEPRECATION")
    private suspend fun createPresentationExchange(
        request: PresentationRequestParameters,
        presentation: CredentialPresentation.PresentationExchangePresentation,
        matchPresentationExchange: suspend (PresentationExchangeRequest) -> KmmResult<HolderPresentationExchangeQueryMatchingResult<StoreEntry>>,
    ): PresentationResponseParameters.PresentationExchangeParameters {
        val presentationRequest = presentation.presentationRequest
        val presentationDefinition = presentationRequest.presentationDefinition
        val selection = presentation.inputDescriptorSubmissions
            ?: matchPresentationExchange(presentation.presentationRequest).getOrThrow().toDefaultSubmission()

        presentationRequest.validateSubmission(selection)
            .onFailure { throw PresentationException(it) }
        val submissions = selection.mapValues {
            PresentationExchangeCredentialDisclosure(
                credential = it.value.credential,
                disclosedAttributes = it.value.disclosedAttributes,
            )
        }.toList()

        return if (request.returnOneDeviceResponse) {
            PresentationResponseParameters.PresentationExchangeParameters(
                presentationSubmission = PresentationSubmission.fromMatches(
                    presentationId = presentationDefinition.id,
                    matches = submissions,
                    isSingleIsoMdocPresentation = true,
                ),
                presentationResults = listOf(
                    verifiablePresentationFactory.createVerifiablePresentation(
                        request = request,
                        isoPresentationParameters = submissions.map {
                            IsoPresentationParameters.create(
                                credential = it.second.credential as StoreEntry.Iso,
                                claims = it.second.disclosedAttributes
                            ).getOrThrow()
                        },
                    ).getOrThrow()
                ),
            )
        } else {
            PresentationResponseParameters.PresentationExchangeParameters(
                presentationSubmission = PresentationSubmission.fromMatches(
                    presentationId = presentationDefinition.id,
                    matches = submissions,
                ),
                presentationResults = submissions.map { match ->
                    verifiablePresentationFactory.createVerifiablePresentation(
                        request = request,
                        credential = match.second.credential,
                        disclosedAttributes = match.second.disclosedAttributes,
                    ).getOrThrow()
                },
            )
        }
    }

    @Suppress("DEPRECATION")
    private fun PresentationExchangeRequest.validateSubmission(
        credentialSubmissions: Map<String, PresentationExchangeCredentialDisclosure<StoreEntry>>,
    ) = catching {
        val validator = PresentationSubmissionValidator.createInstance(presentationDefinition).getOrThrow()
        require(validator.isValidSubmission(credentialSubmissions.keys)) { "Submission requirements are not satisfied" }

        credentialSubmissions.forEach { submission ->
            val inputDescriptor = presentationDefinition.inputDescriptors
                .firstOrNull { it.id == submission.key }
                ?: throw IllegalArgumentException("Invalid input descriptor id: ${submission.key}")
            val credential = submission.value.credential
            val constraintFieldMatches = difInputEvaluator.evaluateInputDescriptorAgainstCredential(
                inputDescriptor = inputDescriptor,
                fallbackFormatHolder = fallbackFormatHolder,
                credentialClaimStructure = CredentialToJsonConverter.toJsonElement(credential),
                credentialFormat = credential.credentialFormat,
                credentialScheme = credential.schemeIdentifier,
                pathAuthorizationValidator = { true },
            ).getOrThrow()
            val disclosedAttributes = submission.value.disclosedAttributes.map { it.toString() }

            constraintFieldMatches.filter { it.key.optional != true }.forEach { constraintField ->
                val allowedPaths = constraintField.value.map { it.normalizedJsonPath.toString() }
                disclosedAttributes.firstOrNull { allowedPaths.contains(it) }
                    ?: throw IllegalArgumentException(inputDescriptor.errorMessage(constraintField))
            }
        }
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
        // OpenID4VP 1.0 section 6.1: use the root for one VP and an indexed path for several VPs.
        path = index?.let { "\$[$it]" } ?: "\$",
    )

    private fun InputDescriptor.errorMessage(field: Map.Entry<ConstraintField, NodeList>): String =
        "Input descriptor constraints are not satisfied: ${details(field)}"

    private fun InputDescriptor.details(field: Map.Entry<ConstraintField, NodeList>): String =
        "${id}.${field.key.id?.let { " Missing field: $it" }}"
}
