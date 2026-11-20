package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Part of the ISO/IEC DIS 18013-5:2026 standard: DocRequest (10.2.3)
 *
 * Fails without any requested name space (`NameSpaces = {+ NameSpace => DataElements}`), and for an
 * [AlternativeDataElementsSet.requestedElement] of [requestInfo] that is not requested in [namespaces], as "The
 * requestedElement shall also be present in the NameSpaces structure" (10.2.4).
 */
@Serializable
data class ItemsRequest(
    @SerialName("docType")
    val docType: String,
    @SerialName("nameSpaces")
    val namespaces: Map<String, ItemsRequestList>,
    @SerialName("requestInfo")
    val requestInfo: DocRequestInfo? = null,
) {
    init {
        require(namespaces.isNotEmpty()) {
            "An ItemsRequest for $docType requests no name space"
        }
        val notRequested = requestInfo?.alternativeDataElements.orEmpty()
            .map { it.requestedElement }
            .filterNot { reference ->
                namespaces[reference.namespace]?.entries.orEmpty()
                    .any { it.dataElementIdentifier == reference.dataElementIdentifier }
            }
        require(notRequested.isEmpty()) {
            "Alternatives are given for data elements that are not requested: $notRequested"
        }
    }
}
