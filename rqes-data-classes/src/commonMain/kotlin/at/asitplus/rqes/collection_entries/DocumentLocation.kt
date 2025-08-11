@file:Suppress("DEPRECATION")

package at.asitplus.rqes.collection_entries

import at.asitplus.rqes.Method
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Class used as part of [CscAuthorizationDetails]
 */
@Serializable
@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.csc.collection_entries.DocumentLocation"))
data class DocumentLocation(
    @SerialName("uri")
    val uri: String,
    @SerialName("method")
    val method: Method,
)
