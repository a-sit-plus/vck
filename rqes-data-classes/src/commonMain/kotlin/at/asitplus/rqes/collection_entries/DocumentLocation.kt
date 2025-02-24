package at.asitplus.rqes.collection_entries

import at.asitplus.rqes.DocumentAccessMode
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Class used as part of [AuthorizationDetails]
 */
@Serializable
data class DocumentLocation(
    @SerialName("uri")
    val uri: String,
    @SerialName("method")
    val method: DocumentAccessMode,
)
