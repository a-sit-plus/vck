package at.asitplus.wallet.lib.procedures.iso

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.AlternativeDataElementsSet
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.ElementReference
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.UseCase
import at.asitplus.wallet.lib.agent.DeviceRequestCredentialDisclosure
import at.asitplus.wallet.lib.agent.IsoPresentationParameters
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.agent.ZkMetadata
import at.asitplus.wallet.lib.cbor.authorityKeyIdentifiers
import at.asitplus.wallet.lib.procedures.iso.DeviceRetrievalProcedure.requireIssuedByRequestedAuthority

/** Submission validation for ISO Device Retrieval requests. */
internal object DeviceRetrievalProcedure {

    /**
     * The use cases of [deviceRequest] (ISO/IEC DIS 18013-5:2026, 10.2.5), or, if it has none, one mandatory use case
     * with one document set of all its document requests, as a request without use cases requires each of them.
     */
    fun useCases(deviceRequest: DeviceRequest): List<UseCase> =
        deviceRequest.deviceRequestInfo?.value?.useCases
            ?: listOf(
                UseCase(
                    mandatory = true,
                    documentSets = listOf(deviceRequest.docRequests.indices.map { it.toUInt() })
                )
            )

    /**
     * Checks [submissions] against [deviceRequest], also those a wallet builds itself, and creates the parameters to
     * present them, in the order of the document requests. The checks:
     *  - the submitted document requests satisfy the [useCases], see [requireUseCasesSatisfied]
     *  - a document request is submitted once, unless its `uniqueDocSetRequired` is `false`, which indicates that "the
     *    mdoc reader [...] can receive multiple instances of responses to this exact DocRequest" (ibid., 10.2.4)
     *  - each submission presents an ISO mdoc of the requested docType, issued by an authority of the requested
     *    `issuerIdentifiers`, and discloses data elements of the credential that answer the document request exactly,
     *    see [isAnsweredExactlyBy]. So a wallet may disclose a later alternative than [at.asitplus.iso.match] selects.
     */
    fun createPresentationParameters(
        deviceRequest: DeviceRequest,
        submissions: Collection<DeviceRequestCredentialDisclosure<StoreEntry>>,
    ): KmmResult<Collection<IsoPresentationParameters>> = catching {
        val submissionsByRequest = submissions.groupBy { it.docRequestIndex }
        submissionsByRequest.keys.firstOrNull { it !in deviceRequest.docRequests.indices }?.let {
            throw PresentationException("There is no document request at index $it")
        }
        requireUseCasesSatisfied(useCases(deviceRequest), submissionsByRequest.keys)

        submissionsByRequest.keys.sorted().flatMap { index ->
            val itemsRequest = deviceRequest.docRequests[index].itemsRequest.value
            val requestSubmissions = submissionsByRequest.getValue(index)
            require(requestSubmissions.size == 1 || itemsRequest.requestInfo?.uniqueDocSetRequired == false) {
                "The document request at index $index may only be submitted once"
            }
            requestSubmissions.map { it.validate(itemsRequest, index) }
        }
    }

    /**
     * Fails unless [submitted], the positions of the submitted document requests, satisfy [useCases]. A use case is
     * satisfied if exactly one of its document sets has only submitted document requests, as "Exactly one DocumentSet
     * has to be satisfied to satisfy the documentsSet" (ISO/IEC DIS 18013-5:2026, 10.2.5), and submitting all document
     * requests of several of its document sets fails. The mdoc "has to satisfy at least one UseCase" and "each UseCase
     * where the mandatory element in the UseCase structure is set to True" (ibid.), and each submitted document request
     * has to be in the satisfied document set of a use case.
     */
    fun requireUseCasesSatisfied(useCases: List<UseCase>, submitted: Set<Int>) {
        val satisfiedSets = useCases.map { useCase ->
            useCase.documentSets.map { set -> set.map { it.toInt() } }.filter { submitted.containsAll(it) }
        }
        val ambiguous = satisfiedSets.indices.filter { satisfiedSets[it].size > 1 }
        require(ambiguous.isEmpty()) {
            "Several document sets of the use cases at $ambiguous are satisfied, but exactly one has to be"
        }
        useCases.forEachIndexed { index, useCase ->
            require(!useCase.mandatory || satisfiedSets[index].isNotEmpty()) {
                "The mandatory use case at index $index is not satisfied"
            }
        }
        require(satisfiedSets.any { it.isNotEmpty() }) { "No use case is satisfied" }
        val unreferenced = submitted - satisfiedSets.flatten().flatten().toSet()
        require(unreferenced.isEmpty()) {
            "The document requests at $unreferenced are in no satisfied document set of a use case"
        }
    }

    /** See [createPresentationParameters]. */
    private fun DeviceRequestCredentialDisclosure<StoreEntry>.validate(
        itemsRequest: ItemsRequest,
        index: Int,
    ): IsoPresentationParameters {
        val credential = credential as? StoreEntry.Iso
            ?: throw PresentationException("Document request at index $index requires an ISO mdoc credential")
        require(credential.schemeIdentifier == itemsRequest.docType) {
            "Credential docType does not match document request at index $index"
        }
        itemsRequest.requireIssuedByRequestedAuthority(credential.issuerSigned)
        val disclosed = disclosedAttributes.map { ElementReference(it.namespace, it.claimName) }.toSet()
        val missing = disclosed - credential.issuerSigned.availableItems().keys
        require(missing.isEmpty()) { "Credential does not contain the disclosed data elements $missing" }
        require(itemsRequest.isAnsweredExactlyBy(disclosed)) {
            "The disclosed data elements $disclosed are not one choice of each requested data element or one of its " +
                    "alternative element sets of the document request at index $index"
        }
        val meta = itemsRequest.requestInfo?.zkRequest?.let { ZkMetadata.IsoMdocZk(it) }
        return IsoPresentationParameters.create(credential, disclosedAttributes, meta).getOrThrow()
    }

    /** The data elements of the `NameSpaces` of this request, in their order. */
    private fun ItemsRequest.requestedElements(): List<ElementReference> =
        namespaces.flatMap { (namespace, requested) ->
            requested.entries.map { ElementReference(namespace, it.dataElementIdentifier) }
        }

    /** The alternative element sets of this requested data element in [alternatives], in their order. */
    private fun ElementReference.alternativeSets(
        alternatives: List<AlternativeDataElementsSet>,
    ): List<List<ElementReference>> = alternatives.filter { it.requestedElement == this }
        .flatMap { it.alternativeElementSets }

    /** The issuer-signed data elements of this mdoc, by their name space and identifier. */
    private fun IssuerSigned.availableItems(): Map<ElementReference, IssuerSignedItem> =
        namespaces.orEmpty().flatMap { (namespace, items) ->
            items.entries.map { ElementReference(namespace, it.value.elementIdentifier) to it.value }
        }.toMap()

    /**
     * Whether [issuerSigned] satisfies the `issuerIdentifiers` of this request, if it has any: one of them is the
     * authority key identifier of a certificate in the `x5chain` of its `IssuerAuth`, as "An mdoc only satisfies the
     * DocRequest if one of the IssuerIdentifier matches" (ISO/IEC DIS 18013-5:2026, 10.2.4).
     *
     * This is no evidence of the issuer: the `x5chain` of an `IssuerAuth` is in its unprotected header (ibid., 12.3.4),
     * which the issuer's signature does not cover, so a presenter can add certificates to it. Only the validation of
     * the credential establishes trust in its issuer.
     */
    private fun ItemsRequest.isIssuedByRequestedAuthority(issuerSigned: IssuerSigned): Boolean {
        val issuerIdentifiers = requestInfo?.issuerIdentifiers ?: return true
        val authorities = issuerSigned.issuerAuth.authorityKeyIdentifiers()
        return issuerIdentifiers.any { identifier -> authorities.any { it.contentEquals(identifier) } }
    }

    /** Fails unless [issuerSigned] matches the requested `issuerIdentifiers`, see [isIssuedByRequestedAuthority]. */
    private fun ItemsRequest.requireIssuedByRequestedAuthority(issuerSigned: IssuerSigned) {
        require(isIssuedByRequestedAuthority(issuerSigned)) {
            "Credential is not issued by an authority of the requested issuer identifiers"
        }
    }

    /**
     * Whether [disclosed] answers this request exactly: it is the union of one choice per requested data element, the
     * element itself or all data elements of one of its alternative element sets (ISO/IEC DIS 18013-5:2026, 10.2.4,
     * 10.2.8 step 1d), so that it satisfies the request and discloses nothing else, e.g. not a requested data element
     * together with a part of its alternative element set.
     */
    private fun ItemsRequest.isAnsweredExactlyBy(disclosed: Set<ElementReference>): Boolean {
        val alternatives = requestInfo?.alternativeDataElements.orEmpty()
        val choices = requestedElements().map { element ->
            (listOf(listOf(element)) + element.alternativeSets(alternatives)).filter { disclosed.containsAll(it) }
        }
        if (choices.any { it.isEmpty() }) return false
        val forced = choices.filter { it.size == 1 }.flatMap { it.single() }.toSet()
        return choices.filter { it.size > 1 }.coverExactly(disclosed, forced)
    }

    /** Whether one choice of each entry, added to [covered], is exactly [target]; every choice is part of [target]. */
    private fun List<List<List<ElementReference>>>.coverExactly(
        target: Set<ElementReference>,
        covered: Set<ElementReference>,
    ): Boolean = if (isEmpty()) covered == target
    else first().any { choice -> drop(1).coverExactly(target, covered + choice) }
}
