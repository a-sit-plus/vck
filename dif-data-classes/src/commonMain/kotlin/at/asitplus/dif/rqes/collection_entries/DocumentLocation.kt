package at.asitplus.dif.rqes.collection_entries

import at.asitplus.dif.rqes.Method
import io.ktor.http.*
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
    val method: Method,
)