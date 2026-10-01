package at.asitplus.wallet.lib.procedures.iso

import at.asitplus.KmmResult
import at.asitplus.catching
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
            val requiredPaths = evaluateItemsRequestAgainstCredential(
                itemsRequest = itemsRequest,
                issuerSigned = credential.issuerSigned,
            ).getOrThrow().map {
                NormalizedJsonPath() + it.namespace + it.claimName
            }.toSet()
            require(
                submission.disclosedAttributes.map { it.toString() }.toSet() ==
                        requiredPaths.map { it.toString() }.toSet()
            ) {
                "Disclosed attributes do not exactly match document request at index $index"
            }
            IsoPresentationParameters.create(credential, submission.disclosedAttributes, meta).getOrThrow()
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
                ).getOrNull()?.let { requestedClaims ->
                    IsoDeviceRetrievalCredentialMatch(
                        credentialIndex = index,
                        requestedClaims = requestedClaims,
                    )
                }
            }
    }

    /**
     * Returns all requested claims only if the credential contains every requested namespace and data element.
     * `intentToRetain` controls verifier retention and does not make an element optional.
     */
    private fun evaluateItemsRequestAgainstCredential(
        itemsRequest: ItemsRequest,
        issuerSigned: IssuerSigned,
    ): KmmResult<List<IsoDeviceRetrievalClaimMatch>> = catching {
        itemsRequest.namespaces.flatMap { (namespace, requestedItems) ->
            requestedItems.entries.map { request ->
                val item = issuerSigned.namespaces?.get(namespace)?.entries
                    ?.firstOrNull { it.value.elementIdentifier == request.dataElementIdentifier }
                    ?.value
                    ?: throw PresentationException(
                        "Credential does not contain requested data element $['$namespace']['${request.dataElementIdentifier}']"
                    )
                IsoDeviceRetrievalClaimMatch(
                    namespace = namespace,
                    claimName = item.elementIdentifier,
                    claimValue = item.elementValue,
                )
            }
        }
    }
}
