package at.asitplus.dcapi.ios

import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import io.github.z4kn4fein.semver.Version
import kotlinx.serialization.Serializable

/**
 * iOS-only summary of the mdoc data elements shown by the system before the wallet receives the full Annex C request.
 *
 * Use [isConsistentWith] after receiving the full request and reject the flow when it returns `false`. Comparison is
 * independent of document, namespace, and data-element ordering, but includes each `intentToRetain` value.
 */
@Serializable
data class IosDcApiMdocPreRequestSummary(
    val documentRequests: List<IosDcApiMdocPreRequestDocumentRequest>
) {
    /** Checks that the full request asks for exactly the documents and data elements shown in this summary. */
    fun isConsistentWith(rawRequest: IsoMdocRequest): Boolean =
        normalizedDocumentRequests() == rawRequest.normalizedDocumentRequests()

    @Suppress("DEPRECATION")
    @Deprecated("Support for Presentation Exchange been removed, use toDeviceRequest")
    fun toDifInputDescriptors(): List<DifInputDescriptor> = listOf()

    /** Converts the summary into an ISO device request for pre-request credential matching. */
    fun toDeviceRequest(): DeviceRequest = DeviceRequest(
        parsedVersion = Version(1, 0),
        docRequests = documentRequests.map { request ->
            DocRequest(
                itemsRequest = ByteStringWrapper(
                    ItemsRequest(
                        docType = request.docType,
                        namespaces = request.namespaces.mapValues { (_, elements) ->
                            ItemsRequestList(
                                elements.map { (element, intentToRetain) ->
                                    SingleItemsRequest(element, intentToRetain)
                                }
                            )
                        },
                    )
                )
            )
        }.toTypedArray(),
    )

    private fun normalizedDocumentRequests(): List<IosDcApiMdocPreRequestNormalizedDocumentRequest> =
        documentRequests.map { it.normalize() }.sorted()
}

/** One document and its requested namespace/data-element pairs from the iOS pre-request summary. */
@Serializable
data class IosDcApiMdocPreRequestDocumentRequest(
    val docType: String,
    val namespaces: Map<String, Map<String, Boolean>>
) {
    fun normalize(): IosDcApiMdocPreRequestNormalizedDocumentRequest =
        IosDcApiMdocPreRequestNormalizedDocumentRequest(
            docType = docType,
            namespaces = namespaces.entries
                .sortedBy { it.key }
                .associate { (namespace, elements) ->
                    namespace to elements.entries
                        .sortedBy { it.key }
                        .associate { it.key to it.value }
                }
        )
}

data class IosDcApiMdocPreRequestNormalizedDocumentRequest(
    val docType: String,
    val namespaces: Map<String, Map<String, Boolean>>
) : Comparable<IosDcApiMdocPreRequestNormalizedDocumentRequest> {
    override fun compareTo(other: IosDcApiMdocPreRequestNormalizedDocumentRequest): Int =
        compareValuesBy(
            this,
            other,
            IosDcApiMdocPreRequestNormalizedDocumentRequest::docType,
            { it.namespaces.toString() }
        )
}

private fun IsoMdocRequest.normalizedDocumentRequests(): List<IosDcApiMdocPreRequestNormalizedDocumentRequest> =
    deviceRequest.docRequests.map { docRequest ->
        IosDcApiMdocPreRequestNormalizedDocumentRequest(
            docType = docRequest.itemsRequest.value.docType,
            namespaces = docRequest.itemsRequest.value.namespaces.entries
                .sortedBy { it.key }
                .associate { (namespace, items) ->
                    namespace to items.entries
                        .map { it.dataElementIdentifier to it.intentToRetain }
                        .sortedBy { it.first }
                        .associate { it.first to it.second }
                }
        )
    }.sorted()
