package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for Server retrieval mdoc request (8.3.2.2.2.1)
 */
@Serializable
data class ServerItemsRequest(
    @SerialName("docType")
    val docType: String,
    @SerialName("nameSpaces")
    val namespaces: Map<String, Map<String, Boolean>>,
    @SerialName("requestInfo")
    val requestInfo: Map<String, String>? = null,
)