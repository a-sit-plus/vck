package at.asitplus.csc.bindings

import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.csc.datamodel.documents.SignatureRequestContent
import kotlinx.serialization.KeepGeneratedSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** A CSC Data Model Bindings 6.2.1 signature request flattened as required by TS 119 432 Annex A.6.4. */
@KeepGeneratedSerializer
@Serializable(with = QesSignatureRequestSerializer::class)
data class QesSignatureRequest(
    /** CSC Data Model 1.0.0 document data or reference to be signed. */
    val document: SignatureRequestContent,
    /** CSC Data Model 1.0.0 AdES format, conformance, and signed-property options. */
    val adesParameters: AdesParameters = AdesParameters(),
    /** TS 119 432 Annex A.6.4: Algorithm requested for creating this document's signature. */
    val signingAlgorithm: SigningAlgorithm? = null,
    /** CSC Data Model 1.0.0 callback URI for the signature result. */
    @SerialName("responseURI")
    val responseUri: String? = null,
)
