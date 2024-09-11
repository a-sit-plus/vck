package at.asitplus.dif.rqes

import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DocumentLocationEntry(
    @SerialName("uri")
    @Serializable(UrlSerializer::class)
    val uri: Url,
    @SerialName("method")
    val method: Method,
)
