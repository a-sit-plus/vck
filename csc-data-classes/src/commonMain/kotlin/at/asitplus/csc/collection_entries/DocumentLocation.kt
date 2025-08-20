package at.asitplus.csc.collection_entries

import at.asitplus.csc.Method
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Class used as part of [at.asitplus.openid.qes.CscAuthorizationDetails]
 */
@Serializable
data class DocumentLocation(
    @SerialName("uri")
    val uri: String,
    @SerialName("method")
    val method: Method,
)
