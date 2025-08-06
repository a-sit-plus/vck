@file:Suppress("DEPRECATION")

package at.asitplus.rqes.collection_entries

import at.asitplus.rqes.Method
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
