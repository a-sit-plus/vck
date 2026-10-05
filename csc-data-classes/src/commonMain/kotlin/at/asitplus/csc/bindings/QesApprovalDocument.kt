package at.asitplus.csc.bindings

import at.asitplus.csc.datamodel.documents.DocumentInfo
import at.asitplus.csc.datamodel.documents.DocumentReference
import kotlinx.serialization.KeepGeneratedSerializer
import kotlinx.serialization.Serializable


/**
 * CSC Data Model Bindings 1.0.0 section 7.1 / ETSI TS 119 432 Annex B.6.2: REQUIRED
 * Document entry for qesApprovalRequest. At least one of [documentInfo] or [documentReference] is required.
 */
@KeepGeneratedSerializer
@Serializable(with = QesApprovalDocumentSerializer::class)
data class QesApprovalDocument(
    /**
     * CSC Data Model 1.0.0 section 8.2: OPTIONAL
     * Document information form.
     */
    val documentInfo: DocumentInfo? = null,
    /**
     * ETSI TS 119 432 Annex B.6.2: OPTIONAL
     * Remote document reference extension.
     */
    val documentReference: DocumentReference? = null,
) {
    init {
        require(documentInfo != null || documentReference != null) {
            "At least one of documentInfo or documentReference must be provided"
        }
    }
}
