package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper

/**
 * Requests [docRequests] as the [useCases] say, like DCQL credential sets do (OpenID4VP 1.0, 6.2, 6.4.2): the mdoc
 * "has to satisfy at least one UseCase", every mandatory one, and exactly one document set of each it satisfies
 * (ISO/IEC DIS 18013-5:2026, 10.2.5). A document set lists the positions of document requests in [docRequests].
 *
 * If the use cases only say that every document request is required, i.e. they are all mandatory, each with one
 * document set and without purpose hints, and together they reference every document request, the request has no
 * `deviceRequestInfo` and version 1.0, which is how an mdoc of ISO/IEC 18013-5:2021 reads it anyway. Otherwise the
 * use cases are its `deviceRequestInfo`, in version 1.1 (ibid., 10.2.2).
 *
 * Fails without [useCases]; for a document set referencing a document request that does not exist; for a document
 * request no use case references, which nothing would request: leave it out instead; and for a use case with a
 * document set contained in another one of it, e.g. `[pid, mdl]` and `[pid]`, as "Exactly one DocumentSet has to be
 * satisfied" (ibid., 10.2.5), so presenting the larger one, which satisfies both, would never satisfy the use case.
 * Request the contained one in a mandatory use case, and the rest in an optional one instead, e.g. `[pid]` and
 * `[mdl]`.
 */
fun DeviceRequest.Companion.forUseCases(
    docRequests: List<DocRequest>,
    useCases: List<UseCase>
): DeviceRequest {
    require(useCases.isNotEmpty()) {
        "At least one use case is required"
    }
    val referenced = useCases.flatMap { useCase -> useCase.documentSets.flatten() }.toSet()
    val missing = referenced.filter { it >= docRequests.size.toUInt() }
    require(missing.isEmpty()) {
        "Use cases reference the document requests $missing, but there are ${docRequests.size}"
    }
    val unreferenced = docRequests.indices.filter { it.toUInt() !in referenced }
    require(unreferenced.isEmpty()) {
        "No use case references the document requests at $unreferenced"
    }
    val nested = useCases.indices.filter { useCases[it].hasNestedDocumentSets() }
    require(nested.isEmpty()) {
        "The use cases at $nested have a document set contained in another one, " +
                "so that exactly one of them can never be satisfied"
    }
    val everyDocRequestRequired = useCases.all {
        it.mandatory && it.documentSets.size == 1 && it.purposeHints == null
    }
    return if (everyDocRequestRequired) {
        DeviceRequest(
            parsedVersion = IsoConstants.VERSION_1_0,
            docRequests = docRequests.toTypedArray(),
            deviceRequestInfo = null,
        )
    } else {
        DeviceRequest(
            parsedVersion = IsoConstants.VERSION_1_1,
            docRequests = docRequests.toTypedArray(),
            deviceRequestInfo = ByteStringWrapper(DeviceRequestInfo(useCases = useCases)),
        )
    }
}

/** Whether a document set of this use case contains another one of it, or equals it. */
private fun UseCase.hasNestedDocumentSets(): Boolean = documentSets.withIndex().any { outer ->
    documentSets.withIndex().any { inner -> inner.index != outer.index && outer.value.containsAll(inner.value) }
}
