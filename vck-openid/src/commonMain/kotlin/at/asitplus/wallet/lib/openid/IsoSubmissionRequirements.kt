package at.asitplus.wallet.lib.openid

import at.asitplus.iso.Document
import at.asitplus.iso.ItemsRequest
import at.asitplus.wallet.lib.validation.CheckOutcome

/**
 * Whether every document request of this `DeviceRequest` is answered by its own document of the accepted [documents]
 * of a response: one of its docType that returns every requested data element issuer-signed.
 *
 * The mdoc may return only some of the requested documents, and error codes instead of some requested data elements
 * (ISO/IEC 18013-5:2021, 8.3.2.1.2.2), which does not satisfy the request, as VC-K requests only the data elements it
 * requires (see `RequestedCredential.Mdoc.toDocRequest`). Only issuer-signed data elements count, as only these are
 * attested by the issuer. Documents are assigned to requests regardless of their order in the response, each answering
 * one request at most, so two requests of one docType need two documents.
 */
internal fun List<ItemsRequest>.submissionRequirements(documents: List<Document>): CheckOutcome =
    if (answerable(this, documents))
        CheckOutcome.Passed
    else
        CheckOutcome.Failed(
            IllegalArgumentException("No accepted documents answer ${joinToString { it.describe() }}, one document each")
        )

/**
 * Whether each of [requests] can be answered by its own document of [documents], trying every assignment: a
 * `DeviceRequest` has few document requests, so this is cheap, and it does not depend on the order of either.
 */
private fun answerable(requests: List<ItemsRequest>, documents: List<Document>): Boolean =
    requests.isEmpty() || documents.indices.any { index ->
        requests.first().isAnsweredBy(documents[index]) &&
                answerable(requests.drop(1), documents.filterIndexed { other, _ -> other != index })
    }

/** Whether [document] is of the docType of this request and returns each requested data element issuer-signed. */
private fun ItemsRequest.isAnsweredBy(document: Document): Boolean {
    if (document.docType != docType)
        return false
    val returned = document.issuerSigned.namespaces.orEmpty().mapValues { (_, items) ->
        items.entries.map { it.value.elementIdentifier }.toSet()
    }
    return namespaces.all { (namespace, requested) ->
        val elements = returned[namespace].orEmpty()
        requested.entries.all { it.dataElementIdentifier in elements }
    }
}

private fun ItemsRequest.describe() =
    "$docType ${namespaces.mapValues { (_, requested) -> requested.entries.map { it.dataElementIdentifier } }}"
