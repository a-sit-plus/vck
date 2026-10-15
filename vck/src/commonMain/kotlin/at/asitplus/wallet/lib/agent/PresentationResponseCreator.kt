@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceRequest
import at.asitplus.openid.QesApprovalRequest
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.openid.dcql.DCQLIsoMdocZkCredentialQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.toTransactionData
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.procedures.iso.DeviceRetrievalProcedure

private typealias QesApprovalSubmission = Pair<DCQLCredentialQueryIdentifier, Int>

/** Resolves and validates holder submissions before creating their format-specific response artifacts. */
internal class PresentationResponseCreator(
    private val verifiablePresentationFactory: VerifiablePresentationFactory,
) {

    suspend fun create(
        request: PresentationRequestParameters,
        credentialPresentation: CredentialPresentation,
        matchDCQLQuery: suspend (DCQLQuery) -> KmmResult<HolderDCQLQueryMatchingResult<StoreEntry>>,
        matchDeviceRequest: suspend (DeviceRequest) -> KmmResult<HolderIsoDeviceRetrievalQueryMatchingResult<StoreEntry>>,
    ): KmmResult<PresentationResponseParameters> = catching {
        when (credentialPresentation) {
            is CredentialPresentation.DCQLPresentation ->
                createDcql(
                    request,
                    credentialPresentation,
                    matchDCQLQuery
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

        val approvals = selectQesApprovals(request.transactionData, dcqlQuery, credentialSubmissions)
        val presentations = credentialSubmissions.mapValues { (queryId, submissions) ->
            val query = dcqlQuery.credentials.first { it.id == queryId }
            if (!query.multiple && submissions.size != 1) {
                throw IllegalArgumentException(
                    "Credential query ${query.id} does not allow multiple submission, but ${submissions.size} were provided."
                )
            }
            submissions.mapIndexed { submissionIndex, it ->
                val credential = it.credential
                if (credential is StoreEntry.Vc && !query.requireCryptographicHolderBinding) {
                    if (it.matchingResult !is DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult) {
                        throw IllegalArgumentException("Credential type only allows disclosure of all attributes.")
                    }
                    CreatePresentationResult.VcJws(credential.vcSerialized)
                } else {
                    verifiablePresentationFactory.createVerifiablePresentation(
                        request = request.copy(
                            qesApprovalTransactionData = listOfNotNull(approvals[queryId to submissionIndex]),
                        ),
                        credential = credential,
                        disclosedAttributes = it.matchingResult,
                        zkMetadata = when (query) {
                            is DCQLIsoMdocZkCredentialQuery -> ZkMetadata.IsoMdocZk(query.meta.zkSystemType.toZkRequest())
                            else -> null
                        }
                    ).getOrThrow()
                }
            }
        }

        return PresentationResponseParameters.DCQLParameters(presentations)
    }

    /**
     * OpenID4VP 1.0 section 5.1 requires one authorizing credential per transaction, even when credential_ids
     * lists alternatives. Select one submitted credential in DCQL request order before any signatures are made.
     * Prefer an unused submission, reassigning earlier approvals to another alternative when necessary, since
     * each qesApproval field carries one digest. Preserve the original encoded data for the format-specific hash input.
     */
    private fun selectQesApprovals(
        transactionData: List<TransactionDataBase64Url>?,
        query: DCQLQuery,
        submissions: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<StoreEntry>>>,
    ): Map<QesApprovalSubmission, TransactionDataBase64Url> {
        val approvals = findQesApprovals(transactionData)
        if (approvals.isEmpty()) return emptyMap()

        val candidates = approvals.map { (_, approval) ->
            findQesApprovalCandidates(approval, query, submissions)
        }
        val selected = assignQesApprovals(candidates)
        return selected.mapValues { (_, approvalIndex) -> approvals[approvalIndex].first }
    }

    private fun findQesApprovals(
        transactionData: List<TransactionDataBase64Url>?,
    ): List<Pair<TransactionDataBase64Url, QesApprovalRequest>> = transactionData.orEmpty().mapNotNull { encoded ->
        (encoded.toTransactionData() as? QesApprovalRequest)?.let { encoded to it }
    }

    private fun findQesApprovalCandidates(
        approval: QesApprovalRequest,
        query: DCQLQuery,
        submissions: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<StoreEntry>>>,
    ): List<QesApprovalSubmission> {
        val queryIds = query.credentials.map { it.id.string }.toSet()
        if (approval.credentialIds.isEmpty()) {
            throw PresentationException("QES approval credential_ids must be present and non-empty for DCQL")
        }
        if (!queryIds.containsAll(approval.credentialIds)) {
            throw PresentationException("QES approval credential_ids references an unknown DCQL query")
        }

        return query.credentials.filter { it.id.string in approval.credentialIds }
            .flatMap { credentialQuery ->
                submissions[credentialQuery.id].orEmpty().mapIndexedNotNull { index, submission ->
                    when (submission.credential) {
                        is StoreEntry.SdJwt, is StoreEntry.Iso -> credentialQuery.id to index
                        else -> null
                    }
                }
            }.also {
                if (it.isEmpty()) {
                    throw PresentationException("No selected credential can authorize the QES approval")
                }
            }
    }

    private fun assignQesApprovals(
        candidates: List<List<QesApprovalSubmission>>,
    ): Map<QesApprovalSubmission, Int> {
        val selected = mutableMapOf<QesApprovalSubmission, Int>()
        candidates.indices.forEach { index ->
            if (!tryAssignQesApproval(index, candidates, selected, mutableSetOf())) {
                throw PresentationException("Only one qesApprovalRequest may be presented per credential submission")
            }
        }
        return selected
    }

    private fun tryAssignQesApproval(
        approvalIndex: Int,
        candidates: List<List<QesApprovalSubmission>>,
        selected: MutableMap<QesApprovalSubmission, Int>,
        visited: MutableSet<QesApprovalSubmission>,
    ): Boolean {
        for (target in candidates[approvalIndex].sortedBy { it in selected }) {
            if (!visited.add(target)) continue
            val previous = selected[target]
            if (previous == null || tryAssignQesApproval(previous, candidates, selected, visited)) {
                selected[target] = approvalIndex
                return true
            }
        }
        return false
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

}
