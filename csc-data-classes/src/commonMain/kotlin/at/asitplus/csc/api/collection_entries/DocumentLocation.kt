package at.asitplus.csc.api.collection_entries

import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.csc.api.Method
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
    val method: Method,
) {
    /** Lossless migration to the CSC Data Model 1.0 representation. */
    fun toCsc22(): DocumentReference = DocumentReference(href = uri, access = method.toCsc22())
}
