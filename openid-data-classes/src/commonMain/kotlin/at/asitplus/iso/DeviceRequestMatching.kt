package at.asitplus.iso

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped

/*
 * The rules of a DeviceRequest (ISO/IEC DIS 18013-5:2026, 10.2) over the credentials of a holder and the documents of
 * a response, the counterpart of the rules of a DCQL query in at.asitplus.openid.dcql.
 */

/** The identifiers of the document requests of this request, in their order, see [DocRequestId]. */
val DeviceRequest.docRequestIds: List<DocRequestId>
    get() = docRequests.indices.map { DocRequestId(it) }

/** The [ItemsRequest] of the document request [id] of this request. Fails if this request has none at [id]. */
fun DeviceRequest.itemsRequest(id: DocRequestId): ItemsRequest =
    requireNotNull(docRequests.getOrNull(id.index)) { "There is no document request $id" }.itemsRequest.value

/**
 * The use cases of this request (ISO/IEC DIS 18013-5:2026, 10.2.5), or, if it has none, one mandatory use case
 * with one document set of all its document requests, as a request without use cases requires each of them.
 */
val DeviceRequest.requestedUseCases: List<UseCase>
    get() = deviceRequestInfo?.value?.useCases
        ?: listOf(UseCase(mandatory = true, documentSets = listOf(docRequests.indices.map { it.toUInt() })))

/**
 * How each of [credentials] answers each document request of this request, see [ItemsRequest.match], like
 * [at.asitplus.openid.dcql.DCQLQuery.findCredentialQueryMatches]: for each document request one result per credential,
 * in the order of [credentials], failures included.
 */
fun DeviceRequest.findDocRequestMatches(
    credentials: List<IsoMdocCredential>,
): DeviceRequestMatchingResult = DeviceRequestMatchingResult(
    docRequestMatchingResults = docRequestIds.associateWith { id ->
        val itemsRequest = itemsRequest(id)
        credentials.map { itemsRequest.match(it) }
    }
)

/**
 * The data elements of [credential] to disclose for this request (ISO/IEC DIS 18013-5:2026, 10.2.8 step 1):
 *  - for each requested data element, the element itself if the credential has it, otherwise the first of its
 *    alternative element sets (`alternativeDataElements`) whose data elements the credential all has, as "The
 *    order of the data elements in AlternativeElementSets indicates the order of preference" (ibid., 10.2.4);
 *    alternatives are not the End-User's choice, like DCQL claim combinations (OpenID4VP 1.0, 6.4.1)
 *  - each data element once, also if it replaces several requested ones, as "that data element is still only
 *    returned once in the response structure" (ISO/IEC DIS 18013-5:2026, 10.2.4)
 *
 * Fails if the credential is not of the requested docType, if it is not issued by an authority of the requested
 * `issuerIdentifiers`, see [isAnsweredBy], and if a requested data element is missing without an available
 * alternative. `intentToRetain` controls verifier retention and does not make an element optional.
 */
fun ItemsRequest.match(credential: IsoMdocCredential): KmmResult<DocRequestMatch> = catching {
    requireDocType(credential)
    requireIssuedByRequestedAuthority(credential)
    val available = credential.issuerSignedItems
    val alternatives = requestInfo?.alternativeDataElements.orEmpty()
    DocRequestMatch(
        disclosedItems = requestedElements()
            .flatMap { it.selectFrom(available.keys, alternatives) }
            .distinct()
            .associateWith { available.getValue(it) }
    )
}

/**
 * Fails unless [submitted], the submitted document requests, satisfy the [requestedUseCases] of this request, like
 * [at.asitplus.openid.dcql.DCQLQuery.checkCredentialSetQueryRequirements]. A use case is satisfied if exactly one of its
 * document sets has only submitted document requests, as "Exactly one DocumentSet has to be satisfied to satisfy the
 * documentsSet" (ISO/IEC DIS 18013-5:2026, 10.2.5), and submitting all document requests of several of its document
 * sets fails. The mdoc "has to satisfy at least one UseCase" and "each UseCase where the mandatory element in the
 * UseCase structure is set to True" (ibid.), and each submitted document request has to be one of this request, in the
 * satisfied document set of a use case.
 */
fun DeviceRequest.checkUseCaseRequirements(submitted: Set<DocRequestId>): KmmResult<Unit> = catching {
    val unknown = submitted - docRequestIds.toSet()
    require(unknown.isEmpty()) { "There are no document requests $unknown" }
    requireUseCasesSatisfied(requestedUseCases, submitted)
}

/**
 * Fails unless disclosing [disclosed] of [credential] answers this request exactly, as the holder's submission has to:
 * the credential is of the requested docType, issued by an authority of the requested `issuerIdentifiers`, see
 * [isAnsweredBy], and has the data elements [disclosed], which are the union of one choice per requested data element,
 * the element itself or all data elements of one of its alternative element sets (ISO/IEC DIS 18013-5:2026, 10.2.4,
 * 10.2.8 step 1d), so that they satisfy the request and disclose nothing else, e.g. not a requested data element
 * together with a part of its alternative element set.
 *
 * So a holder may disclose a later alternative than [match] selects.
 */
fun ItemsRequest.checkDisclosure(
    credential: IsoMdocCredential,
    disclosed: Set<ElementReference>,
): KmmResult<Unit> = catching {
    requireDocType(credential)
    requireIssuedByRequestedAuthority(credential)
    val missing = disclosed - credential.issuerSignedItems.keys
    require(missing.isEmpty()) { "Credential does not contain the disclosed data elements $missing" }
    require(isAnsweredExactlyBy(disclosed)) {
        "The disclosed data elements $disclosed are not one choice of each requested data element or one of its " +
                "alternative element sets of the document request for $docType"
    }
}

/**
 * Whether [credential], e.g. a document of a response, answers this request, as a verifier checks it: it is of the
 * requested docType, matches its `issuerIdentifiers`, and has, issuer-signed, each requested data element or all data
 * elements of one of its alternative element sets (ISO/IEC DIS 18013-5:2026, 10.2.8 step 1d). Unlike [checkDisclosure],
 * further data elements do not matter.
 *
 * The `issuerIdentifiers` are satisfied if one of them is an authority key identifier of [credential], see
 * [IsoMdocCredential.authorityKeyIdentifiers], as "An mdoc only satisfies the DocRequest if one of the
 * IssuerIdentifier matches" (ibid., 10.2.4). This is no evidence of the issuer: the `x5chain` of an `IssuerAuth` is in
 * its unprotected header (ibid., 12.3.4), which the issuer's signature does not cover, so a presenter can add
 * certificates to it. Only the validation of the credential establishes trust in its issuer.
 */
fun ItemsRequest.isAnsweredBy(credential: IsoMdocCredential): Boolean =
    credential.docType == docType &&
            isIssuedByRequestedAuthority(credential) &&
            isSatisfiedBy(credential.issuerSignedItems.keys)

/**
 * Fails unless [documents], e.g. the accepted ones of a response, satisfy this request, as a verifier checks it:
 * some document requests satisfy its use cases (a request without use cases requires every document request), as the
 * wallet has to submit them, see [checkUseCaseRequirements], and each of them is answered by its own document, see
 * [ItemsRequest.isAnsweredBy] (ISO/IEC DIS 18013-5:2026, 10.2.4, 10.2.8 step 1).
 *
 * Further documents, e.g. a second one of a requested docType, are ignored. Documents are assigned regardless of their
 * order, each to one document request at most, so two requests of one docType need two documents.
 *
 * The search tries each choice of at most one document set per use case, at most the product of the number of
 * document sets plus one over the use cases, and for each the assignments of documents to its document requests;
 * a `DeviceRequest` has few of both.
 */
fun DeviceRequest.checkAcceptedDocuments(documents: List<IsoMdocCredential>): KmmResult<Unit> = catching {
    val useCases = requestedUseCases
    val answering = docRequestIds.associateWith { id ->
        val itemsRequest = itemsRequest(id)
        documents.indices.filter { itemsRequest.isAnsweredBy(documents[it]) }
    }
    val satisfied = useCases.choices().any { submitted ->
        catchingUnwrapped { requireUseCasesSatisfied(useCases, submitted) }.isSuccess &&
                assignable(submitted.sortedBy { it.index }, answering, setOf())
    }
    require(satisfied) { "No documents satisfy the use cases of ${describe()}, one document each" }
}

/** See [checkUseCaseRequirements]. */
private fun requireUseCasesSatisfied(useCases: List<UseCase>, submitted: Set<DocRequestId>) {
    val satisfiedSets = useCases.map { useCase ->
        useCase.docRequestIdSets().filter { submitted.containsAll(it) }
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
        "The document requests $unreferenced are in no satisfied document set of a use case"
    }
}

/**
 * The document sets of this use case, by the identifiers of their document requests, which are positions in
 * [DeviceRequest.docRequests], as [DeviceRequest] rejects use cases that reference other positions.
 */
private fun UseCase.docRequestIdSets(): List<List<DocRequestId>> =
    documentSets.map { set -> set.map { DocRequestId(it.toInt()) } }

/** The document requests of each choice of at most one document set per use case, except the empty choice. */
private fun List<UseCase>.choices(): Sequence<Set<DocRequestId>> =
    fold(sequenceOf(setOf<DocRequestId>())) { choices, useCase ->
        choices.flatMap { chosen ->
            sequenceOf(chosen) + useCase.docRequestIdSets().asSequence().map { set -> chosen + set }
        }
    }.filter { it.isNotEmpty() }

/**
 * Whether each of [docRequests] can be answered by its own document of [answering], the indices of the documents that
 * answer each document request, none of [used].
 */
private fun assignable(
    docRequests: List<DocRequestId>,
    answering: Map<DocRequestId, List<Int>>,
    used: Set<Int>,
): Boolean = docRequests.isEmpty() || answering.getValue(docRequests.first()).any { document ->
    document !in used && assignable(docRequests.drop(1), answering, used + document)
}

private fun DeviceRequest.describe(): String = docRequests.joinToString { it.itemsRequest.value.describe() }

private fun ItemsRequest.describe() =
    "$docType ${namespaces.mapValues { (_, requested) -> requested.entries.map { it.dataElementIdentifier } }}"

private fun ItemsRequest.requireDocType(credential: IsoMdocCredential) {
    require(credential.docType == docType) {
        "Credential docType ${credential.docType} does not match the requested docType $docType"
    }
}

/** See [isAnsweredBy]. */
private fun ItemsRequest.isIssuedByRequestedAuthority(credential: IsoMdocCredential): Boolean {
    val issuerIdentifiers = requestInfo?.issuerIdentifiers ?: return true
    return issuerIdentifiers.any { identifier ->
        credential.authorityKeyIdentifiers.any { it.contentEquals(identifier) }
    }
}

private fun ItemsRequest.requireIssuedByRequestedAuthority(credential: IsoMdocCredential) {
    require(isIssuedByRequestedAuthority(credential)) {
        "Credential is not issued by an authority of the requested issuer identifiers"
    }
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

/**
 * Whether the data elements [available] satisfy this request: for each requested data element, the element itself,
 * or all data elements of one of its alternative element sets (ISO/IEC DIS 18013-5:2026, 10.2.8 step 1d).
 */
private fun ItemsRequest.isSatisfiedBy(available: Set<ElementReference>): Boolean {
    val alternatives = requestInfo?.alternativeDataElements.orEmpty()
    return requestedElements().all { element ->
        element in available || element.alternativeSets(alternatives).any { available.containsAll(it) }
    }
}

/**
 * This requested data element if it is [available], otherwise the first of its alternative element sets in
 * [alternatives] whose data elements are all [available], see [match].
 */
private fun ElementReference.selectFrom(
    available: Set<ElementReference>,
    alternatives: List<AlternativeDataElementsSet>,
): List<ElementReference> = if (this in available) listOf(this) else firstAlternative(available, alternatives)

private fun ElementReference.firstAlternative(
    available: Set<ElementReference>,
    alternatives: List<AlternativeDataElementsSet>,
): List<ElementReference> = alternativeSets(alternatives)
    .firstOrNull { set -> set.all { it in available } }
    ?: throw IllegalArgumentException(
        "Credential does not contain requested data element $['$namespace']['$dataElementIdentifier'], " +
                "nor an alternative"
    )

/** See [checkDisclosure]. */
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
