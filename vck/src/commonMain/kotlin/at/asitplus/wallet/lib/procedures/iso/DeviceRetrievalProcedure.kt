package at.asitplus.wallet.lib.procedures.iso

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.AgeAttestation
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.ItemsRequest
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.wallet.lib.agent.DeviceRequestCredentialDisclosure
import at.asitplus.wallet.lib.agent.IsoDeviceRetrievalClaimMatch
import at.asitplus.wallet.lib.agent.IsoDeviceRetrievalCredentialMatch
import at.asitplus.wallet.lib.agent.IsoDeviceRetrievalQueryMatchingResult
import at.asitplus.wallet.lib.agent.IsoPresentationParameters
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.ZkMetadata
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry

/** Matching and submission validation for ISO Device Retrieval requests. */
internal object DeviceRetrievalProcedure {

    /**
     * Error code for a data element that is not returned, as per ISO/IEC 18013-5:2021, Table 9:
     * "The mdoc does not provide the requested document or data element without any given reason."
     */
    internal const val ERROR_CODE_DATA_NOT_RETURNED = 0

    fun match(
        deviceRequest: DeviceRequest,
        credentials: List<StoreEntry>,
    ) = IsoDeviceRetrievalQueryMatchingResult(
        documentMatches = deviceRequest.docRequests.map { docRequest ->
            docRequest.itemsRequest.value.match(credentials)
        },
    )

    fun validateSubmission(
        deviceRequest: DeviceRequest,
        submissions: Collection<DeviceRequestCredentialDisclosure<StoreEntry>>,
    ): KmmResult<Collection<IsoPresentationParameters>> = catching {
        require(submissions.size == deviceRequest.docRequests.size) {
            "A submission is required for every document request"
        }
        val submissionsByRequest = submissions.associateBy { it.docRequestIndex }
        require(submissionsByRequest.size == submissions.size) { "A document request may only be submitted once" }

        deviceRequest.docRequests.mapIndexed { index, docRequest ->
            val submission = submissionsByRequest[index]
                ?: throw PresentationException("Missing submission for document request at index $index")
            val credential = submission.credential as? StoreEntry.Iso
                ?: throw PresentationException("Document request at index $index requires an ISO mdoc credential")
            val itemsRequest = docRequest.itemsRequest.value
            require(credential.schemeIdentifier == itemsRequest.docType) {
                "Credential docType does not match document request at index $index"
            }
            val meta = itemsRequest.requestInfo?.zkRequest?.let {
                ZkMetadata.IsoMdocZk(it)
            }
            val evaluation = evaluateItemsRequestAgainstCredential(
                itemsRequest = itemsRequest,
                issuerSigned = credential.issuerSigned,
            ).getOrThrow()
            val requiredPaths = evaluation.matches.map {
                NormalizedJsonPath() + it.namespace + it.claimName
            }.toSet()
            require(
                submission.disclosedAttributes.map { it.toString() }.toSet() ==
                        requiredPaths.map { it.toString() }.toSet()
            ) {
                "Disclosed attributes do not exactly match document request at index $index"
            }
            IsoPresentationParameters.create(
                credential = credential,
                claims = submission.disclosedAttributes,
                zkMetadata = meta,
                errors = evaluation.errors,
            ).getOrThrow()
        }
    }

    private fun ItemsRequest.match(
        credentials: List<StoreEntry>,
    ): List<IsoDeviceRetrievalCredentialMatch> = credentials.mapIndexedNotNull { index, credential ->
        (credential as? StoreEntry.Iso)
            ?.takeIf { it.schemeIdentifier == docType }
            ?.let {
                evaluateItemsRequestAgainstCredential(
                    itemsRequest = this,
                    issuerSigned = it.issuerSigned,
                ).getOrNull()?.let { evaluation ->
                    IsoDeviceRetrievalCredentialMatch(
                        credentialIndex = index,
                        requestedClaims = evaluation.matches,
                        unansweredClaims = evaluation.unansweredClaims,
                    )
                }
            }
    }

    /**
     * The claims of [issuerSigned] that answer [itemsRequest], and the requested data elements that cannot be
     * answered.
     *
     * Every requested data element must be present in the credential, with one exception: an age attestation
     * (`age_over_NN`) is resolved according to ISO/IEC 18013-5:2021, 7.2.5, so a request for a threshold the
     * credential does not carry is answered by the nearest attestation that implies it. When no attestation can
     * answer it, 7.2.5 step 3 requires that no `age_over_nn` element be returned — that is a valid response, not
     * a failure, so the element is reported in [ItemsRequestEvaluation.unansweredClaims] and the rest of the
     * request is still satisfied.
     *
     * `intentToRetain` controls verifier retention and does not make an element optional.
     */
    private fun evaluateItemsRequestAgainstCredential(
        itemsRequest: ItemsRequest,
        issuerSigned: IssuerSigned,
    ): KmmResult<ItemsRequestEvaluation> = catching {
        val matches = mutableListOf<IsoDeviceRetrievalClaimMatch>()
        val unanswered = mutableListOf<IsoDeviceRetrievalClaimMatch.Unanswered>()

        itemsRequest.namespaces.forEach { (namespace, requestedItems) ->
            val availableItems = issuerSigned.namespaces?.get(namespace)?.entries
                ?.associate { it.value.elementIdentifier to it.value }
                .orEmpty()
            val availableValues = availableItems.mapValues { it.value.elementValue }

            requestedItems.entries.forEach { request ->
                val requestedIdentifier = request.dataElementIdentifier
                val resolvedIdentifier = AgeAttestation.resolve(requestedIdentifier, availableValues)

                if (resolvedIdentifier == null) {
                    if (AgeAttestation.isAgeAttestation(requestedIdentifier)) {
                        unanswered += IsoDeviceRetrievalClaimMatch.Unanswered(namespace, requestedIdentifier)
                        return@forEach
                    }
                    throw PresentationException(
                        "Credential does not contain requested data element $['$namespace']['$requestedIdentifier']"
                    )
                }

                val item = availableItems.getValue(resolvedIdentifier)
                matches += IsoDeviceRetrievalClaimMatch(
                    namespace = namespace,
                    claimName = item.elementIdentifier,
                    claimValue = item.elementValue,
                    requestedClaimName = requestedIdentifier.takeIf { it != item.elementIdentifier },
                )
            }
        }

        ItemsRequestEvaluation(matches = matches, unansweredClaims = unanswered)
    }

    /** The outcome of evaluating one `ItemsRequest` against one credential. */
    private data class ItemsRequestEvaluation(
        val matches: List<IsoDeviceRetrievalClaimMatch>,
        val unansweredClaims: List<IsoDeviceRetrievalClaimMatch.Unanswered>,
    ) {
        /** [unansweredClaims] in the shape of the mdoc response `errors` structure (8.3.2.1.2.2). */
        val errors: Map<String, Map<String, Int>>
            get() = unansweredClaims
                .groupBy { it.namespace }
                .mapValues { (_, claims) -> claims.associate { it.claimName to ERROR_CODE_DATA_NOT_RETURNED } }
    }
}

