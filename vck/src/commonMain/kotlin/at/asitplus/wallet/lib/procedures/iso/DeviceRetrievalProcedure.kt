package at.asitplus.wallet.lib.procedures.iso

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.AlternativeDataElementsSet
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.ElementReference
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.ItemsRequest
import at.asitplus.wallet.lib.agent.DeviceRequestCredentialDisclosure
import at.asitplus.wallet.lib.agent.IsoDeviceRetrievalClaimMatch
import at.asitplus.wallet.lib.agent.IsoDeviceRetrievalCredentialMatch
import at.asitplus.wallet.lib.agent.IsoDeviceRetrievalQueryMatchingResult
import at.asitplus.wallet.lib.agent.IsoPresentationParameters
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.agent.ZkMetadata
import at.asitplus.wallet.lib.cbor.authorityKeyIdentifiers
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.procedures.iso.DeviceRetrievalProcedure.evaluateItemsRequestAgainstCredential
import io.github.aakira.napier.Napier

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
            val requiredClaims = evaluateItemsRequestAgainstCredential(
                itemsRequest = itemsRequest,
                issuerSigned = credential.issuerSigned,
            ).getOrThrow().map { MdocClaimReference(it.namespace, it.claimName) }.toSet()
            require(submission.disclosedAttributes.toSet() == requiredClaims) {
                "Disclosed attributes do not exactly match document request at index $index"
            }
            IsoPresentationParameters.create(credential, submission.disclosedAttributes, meta).getOrThrow()
        }
    }

    private fun ItemsRequest.match(
        credentials: List<StoreEntry>,
    ): List<IsoDeviceRetrievalCredentialMatch> = credentials.also {
        Napier.d("Matching request for $docType against ${it.size} credential(s)")
    }.mapIndexedNotNull { index, credential ->
        (credential as? StoreEntry.Iso)
            ?.takeIf { it.schemeIdentifier == docType }
            ?.let {
                evaluateItemsRequestAgainstCredential(
                    itemsRequest = this,
                    issuerSigned = it.issuerSigned,
                ).onFailure { error ->
                    Napier.w("Credential at index $index does not match request for $docType", error)
                }.getOrNull()?.let { requestedClaims ->
                    IsoDeviceRetrievalCredentialMatch(
                        credentialIndex = index,
                        requestedClaims = requestedClaims,
                    )
                }
            }
    }

    /**
     * The data elements of [issuerSigned] to disclose for [itemsRequest] (ISO/IEC DIS 18013-5:2026, 10.2.8 step 1):
     *  - for each requested data element, the element itself if the credential has it, otherwise the first of its
     *    alternative element sets (`alternativeDataElements`) whose data elements the credential all has, as "The
     *    order of the data elements in AlternativeElementSets indicates the order of preference" (ibid., 10.2.4);
     *    firstAlternative are not the End-User's choice, like DCQL claim combinations (OpenID4VP 1.0, 6.4.1)
     *  - each data element once, also if it replaces several requested ones, as "that data element is still only
     *    returned once in the response structure" (ISO/IEC DIS 18013-5:2026, 10.2.4)
     *
     * Fails if a requested data element is missing without an available alternative, and if `issuerIdentifiers` are
     * requested, but none is the authority key identifier of a certificate in the `x5chain` of the credential's
     * `IssuerAuth`, as "An mdoc only satisfies the DocRequest if one of the IssuerIdentifier matches" (ibid., 10.2.4).
     * `intentToRetain` controls verifier retention and does not make an element optional.
     */
    private fun evaluateItemsRequestAgainstCredential(
        itemsRequest: ItemsRequest,
        issuerSigned: IssuerSigned,
    ): KmmResult<List<IsoDeviceRetrievalClaimMatch>> = catching {
        itemsRequest.requestInfo?.issuerIdentifiers?.let { issuerIdentifiers ->
            val authorities = issuerSigned.issuerAuth.authorityKeyIdentifiers()
            require(issuerIdentifiers.any { identifier -> authorities.any { it.contentEquals(identifier) } }) {
                "Credential is not issued by an authority of the requested issuer identifiers"
            }
        }
        val availableItems = issuerSigned.namespaces.orEmpty().flatMap { (namespace, items) ->
            items.entries.map { ElementReference(namespace, it.value.elementIdentifier) to it.value }
        }.toMap()
        val alternatives = itemsRequest.requestInfo?.alternativeDataElements.orEmpty()
        itemsRequest.requestedElements()
            .flatMap { it.selectFrom(availableItems.keys, alternatives) }
            .distinct()
            .map { it.toClaimsMatch(availableItems) }
    }

    /** The data elements of the `NameSpaces` of this request, in their order. */
    private fun ItemsRequest.requestedElements(): List<ElementReference> =
        namespaces.flatMap { (namespace, requested) ->
            requested.entries.map { ElementReference(namespace, it.dataElementIdentifier) }
        }

    /**
     * This requested data element if it is [available], otherwise the first of its alternative element sets in
     * [alternatives] whose data elements are all [available], see [evaluateItemsRequestAgainstCredential].
     */
    private fun ElementReference.selectFrom(
        available: Set<ElementReference>,
        alternatives: List<AlternativeDataElementsSet>,
    ): List<ElementReference> = if (this in available) listOf(this) else firstAlternative(available, alternatives)

    private fun ElementReference.firstAlternative(
        available: Set<ElementReference>,
        alternatives: List<AlternativeDataElementsSet>
    ): List<ElementReference> = alternatives.filter { it.requestedElement == this }
        .flatMap { it.alternativeElementSets }
        .firstOrNull { set -> set.all { it in available } }
        ?: throw PresentationException(
            "Credential does not contain requested data element $['$namespace']['$dataElementIdentifier'], " +
                    "nor an alternative"
        )

    private fun ElementReference.toClaimsMatch(
        availableItems: Map<ElementReference, IssuerSignedItem>
    ): IsoDeviceRetrievalClaimMatch = IsoDeviceRetrievalClaimMatch(
        namespace = namespace,
        claimName = dataElementIdentifier,
        claimValue = availableItems.getValue(this).elementValue,
    )
}
