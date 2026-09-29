package at.asitplus.csc.bindings

import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.documents.SignatureRequestContent
import kotlinx.serialization.KeepGeneratedSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** A CSC signature request flattened as required inside the binding's signatureRequests array. */
@KeepGeneratedSerializer
@Serializable(with = QesSignatureRequestSerializer::class)
data class QesSignatureRequest(
    val document: SignatureRequestContent,
    val adesParameters: AdesParameters = AdesParameters(),
    @SerialName("responseURI")
    val responseUri: String? = null,
)
