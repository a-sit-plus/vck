package at.asitplus.dif.rqes.CollectionEntries

import at.asitplus.dif.rqes.Method
import at.asitplus.dif.rqes.Serializer.UrlSerializer
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
