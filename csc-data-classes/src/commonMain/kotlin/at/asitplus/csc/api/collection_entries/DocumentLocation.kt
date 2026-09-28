package at.asitplus.csc.api.collection_entries

import at.asitplus.csc.datamodel.documents.AccessControlMethod
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Class used as part of `at.asitplus.openid.CscAuthorizationDetails`.
 */
@Serializable
data class DocumentLocation(
    @SerialName("uri")
    val uri: String,
    @SerialName("method")
    val method: AccessControlMethod,
)
