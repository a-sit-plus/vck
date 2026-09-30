package at.asitplus.csc.bindings

import at.asitplus.csc.datamodel.documents.DocumentInfo
import at.asitplus.csc.datamodel.documents.DocumentReference
import kotlinx.serialization.KeepGeneratedSerializer
import kotlinx.serialization.Serializable


/** Document entry accepted by CSC Data Model Bindings 7.1 and TS 119 432 Annex B.6.2 for qesApprovalRequest. */
@KeepGeneratedSerializer
@Serializable(with = QesApprovalDocumentSerializer::class)
data class QesApprovalDocument(
    /** CSC Data Model 1.0.0 section 8.2 document information form. */
    val documentInfo: DocumentInfo? = null,
    /** TS 119 432 Annex B.6.2 extension allowing a remote document reference. */
    val documentReference: DocumentReference? = null,
) {
    init {
        require((documentInfo == null) != (documentReference == null)) {
            "Exactly one of documentInfo or documentReference must be provided"
        }
    }
}
