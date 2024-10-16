package at.asitplus.rqes.collection_entries

import at.asitplus.rqes.Method
import at.asitplus.rqes.serializers.UrlSerializer
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Class used as part of [AuthorizationDetails]
 */
@Serializable
data class DocumentLocation(
    @SerialName("uri")
    @Serializable(UrlSerializer::class)
    val uri: Url,
    @SerialName("method")
    val method: Method,
)
