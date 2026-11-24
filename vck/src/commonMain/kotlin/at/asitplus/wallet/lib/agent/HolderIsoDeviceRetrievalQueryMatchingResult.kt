package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DeviceRequestMatchingResult
import at.asitplus.iso.DocRequestId
import at.asitplus.iso.DocRequestSubmissionOption
import at.asitplus.iso.checkUseCaseRequirements
import at.asitplus.iso.itemsRequest
import at.asitplus.iso.requestedUseCases

/**
 * Holder-facing view of an ISO device request match.
 *
 * [deviceRequestMatchingResult] identifies matches by their index in [credentials]. [docRequestMatches] resolves
 * those indices to the actual credentials and the data elements to disclose, and [useCases] shows which document
 * requests the holder can present together, to build a submission with [toSubmission] or [toDefaultSubmission].
 */
data class HolderIsoDeviceRetrievalQueryMatchingResult<Credential : Any>(
    val deviceRequestMatchingResult: DeviceRequestMatchingResult,
    override val credentials: List<Credential>,
    /**
     * The request [deviceRequestMatchingResult] matches, whose use cases (ISO/IEC DIS 18013-5:2026, 10.2.5) and
     * `uniqueDocSetRequired` (ibid., 10.2.4) the submissions follow.
     */
    val deviceRequest: DeviceRequest,
) : HolderPresentationRequestMatchingResult<Credential> {

    /**
     * Matching credentials and the data elements to disclose, by the document request they match, in [credentials]
     * order. The values of the data elements are in the [deviceRequestMatchingResult].
     */
    val docRequestMatches: Map<DocRequestId, List<DocRequestSubmissionOption<Credential>>> =
        deviceRequestMatchingResult.docRequestMatches.mapValues { (_, matches) ->
            matches.map { (index, match) ->
                DocRequestSubmissionOption(
                    credential = credentials[index.toInt()],
                    disclosedElements = match.disclosedElements,
                )
            }
        }

    /**
     * The use cases of [deviceRequest] (ISO/IEC DIS 18013-5:2026, 10.2.5), or one mandatory use case with one document
     * set of all document requests if it has none, each document set with whether the holder can satisfy it, i.e. has
     * a matching credential for each of its document requests.
     * Wallets show these, with their purpose hints, to let the End-User choose a document set of each use case,
     * and whether to present an optional use case, then build the submission with [toSubmission].
     */
    val useCases: List<HolderUseCase> = deviceRequest.requestedUseCases.map { useCase ->
        HolderUseCase(
            mandatory = useCase.mandatory,
            documentSets = useCase.documentSets.map { set -> documentSet(set.map { DocRequestId(it.toInt()) }) },
            purposeHints = useCase.purposeHints.orEmpty(),
        )
    }

    private fun documentSet(docRequestIds: List<DocRequestId>) = HolderDocumentSet(
        docRequestIds = docRequestIds,
        satisfiable = docRequestIds.all { docRequestMatches[it].orEmpty().isNotEmpty() },
    )

    /**
     * The submission of the document set [selection] chooses for each use case to present, both taken from [useCases];
     * an optional use case without an entry is not presented.
     * For each document request of the chosen document sets, by its [DocRequestId], in the order of the document
     * requests, this submits its first matching credential,
     * or every match when its `uniqueDocSetRequired` is `false` (ISO/IEC DIS 18013-5:2026, 10.2.4).
     *
     * Fails if [selection] chooses no document set at all, or none for a mandatory use case,
     * as the mdoc "has to satisfy at least one UseCase" and each mandatory one (ibid., 10.2.5),
     * or chooses a use case or document set that is not in [useCases], or a document set that can not be satisfied,
     * or if the chosen document sets together satisfy several document sets of one use case, e.g. `[0]` for a use case
     * with the document sets `[0]` and `[1]`, and `[1]` for another one, as "Exactly one DocumentSet has to be
     * satisfied" (ibid.).
     */
    fun toSubmission(
        selection: Map<HolderUseCase, HolderDocumentSet>,
    ): KmmResult<Map<DocRequestId, List<DocRequestSubmissionOption<Credential>>>> = catching {
        require(selection.isNotEmpty()) {
            "At least one use case has to be satisfied, but none was chosen"
        }
        selection.entries.forEach { entry ->
            require(entry.key in useCases) {
                "The use case ${entry.key} is not one of the request"
            }
            require(entry.value in entry.key.documentSets) {
                "The document set ${entry.value} is not one of the use case ${entry.key}"
            }
            require(entry.value.satisfiable) {
                "The document set ${entry.value} can not be satisfied"
            }
        }
        useCases.forEachIndexed { useCaseIndex, useCase ->
            require(!useCase.mandatory || useCase in selection) {
                "The use case at $useCaseIndex is mandatory, but no document set was chosen"
            }
        }
        val docRequestIds = selection.values.flatMap { it.docRequestIds }.toSet()
        deviceRequest.checkUseCaseRequirements(docRequestIds).getOrThrow()
        docRequestIds.sortedBy { it.index }.associateWith { id -> firstOrMultiple(id) }
    }

    private fun firstOrMultiple(id: DocRequestId): List<DocRequestSubmissionOption<Credential>> {
        val matches = docRequestMatches[id].orEmpty()
        return if (allowsMultiple(id)) matches else matches.take(1)
    }

    /**
     * Builds a valid automatic submission: [toSubmission] of the first selection that is valid, trying for each
     * mandatory use case its satisfiable document sets, in their order, the earlier use cases varying last, and no
     * optional use case; or, without a mandatory use case, each satisfiable document set of each use case alone, as
     * at least one use case has to be satisfied (ISO/IEC DIS 18013-5:2026, 10.2.5). A later choice is taken when an
     * earlier one satisfies several document sets of one use case, which [toSubmission] rejects.
     *
     * Fails if a mandatory use case, or, without one, every use case can not be satisfied, or no selection is valid.
     * Wallets that obtain a different choice from the End-User use [useCases] and [toSubmission].
     */
    fun toDefaultSubmission(): KmmResult<Map<DocRequestId, List<DocRequestSubmissionOption<Credential>>>> = catching {
        useCases.forEachIndexed { useCaseIndex, useCase ->
            if (useCase.mandatory && useCase.documentSets.none { it.satisfiable })
                throw PresentationException("No document set of the mandatory use case at $useCaseIndex is satisfiable")
        }
        defaultSelections().map { toSubmission(it) }.firstOrNull { it.isSuccess }?.getOrThrow()
            ?: throw PresentationException("No selection of satisfiable document sets satisfies the use cases")
    }

    /** The selections [toDefaultSubmission] tries, in their order. */
    private fun defaultSelections(): Sequence<Map<HolderUseCase, HolderDocumentSet>> {
        val mandatory = useCases.filter { it.mandatory }
        return if (mandatory.isNotEmpty()) mandatory.selections()
        else useCases.asSequence().flatMap { useCase ->
            useCase.documentSets.filter { it.satisfiable }.asSequence().map { mapOf(useCase to it) }
        }
    }

    /** Each combination of one satisfiable document set of each of these use cases, the first one varying last. */
    private fun List<HolderUseCase>.selections(): Sequence<Map<HolderUseCase, HolderDocumentSet>> =
        if (isEmpty()) sequenceOf(mapOf())
        else first().documentSets.filter { it.satisfiable }.asSequence().flatMap { documentSet ->
            drop(1).selections().map { mapOf(first() to documentSet) + it }
        }

    private fun allowsMultiple(id: DocRequestId): Boolean =
        deviceRequest.itemsRequest(id).requestInfo?.uniqueDocSetRequired == false
}

/**
 * A use case of an ISO device request as the holder can satisfy it, see
 * [HolderIsoDeviceRetrievalQueryMatchingResult.useCases].
 */
data class HolderUseCase(
    /** Whether the use case has to be satisfied; if not, the wallet may present it. */
    val mandatory: Boolean,
    /** The document sets of the use case, exactly one of which satisfies it. */
    val documentSets: List<HolderDocumentSet>,
    /** Purpose codes by the ID of the entity that defines them, to tell use cases apart; empty if there are none. */
    val purposeHints: Map<String, Int>,
)

/** A document set of a [HolderUseCase]: document requests to present together. */
data class HolderDocumentSet(
    /** The document requests, by their position in `DeviceRequest.docRequests`. */
    val docRequestIds: List<DocRequestId>,
    /** Whether the holder has a matching credential for each of [docRequestIds]. */
    val satisfiable: Boolean,
)
