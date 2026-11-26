package at.asitplus.iso

/**
 * How an mdoc answers a document request, see [ItemsRequest.match]: the issuer-signed items to disclose, each once,
 * by their name space and data element identifier, as an [IssuerSignedItem] carries no name space
 * (ISO/IEC DIS 18013-5:2026, 10.2.4, 10.2.8 step 1), with their values, e.g. for a wallet to show them.
 *
 * The items are in the order of disclosure: the requested data elements in the order of the request, an alternative
 * element set at the position of the requested data element it replaces.
 */
data class DocRequestMatch(
    val disclosedItems: Map<ElementReference, IssuerSignedItem>,
) {
    /** The data elements to disclose, in the order of [disclosedItems]. */
    val disclosedElements: List<ElementReference>
        get() = disclosedItems.keys.toList()
}
