package at.asitplus.csc.bindings

import at.asitplus.csc.datamodel.documents.DocumentInfo
import at.asitplus.csc.datamodel.documents.DocumentReference
import kotlinx.serialization.KeepGeneratedSerializer
import kotlinx.serialization.Serializable


/** Document entry accepted by the ETSI CSC binding for qesApprovalRequest. */
@KeepGeneratedSerializer
@Serializable(with = QesApprovalDocumentSerializer::class)
data class QesApprovalDocument(
    val documentInfo: DocumentInfo? = null,
    val documentReference: DocumentReference? = null,
) {
    init {
        require((documentInfo == null) != (documentReference == null)) {
            "Exactly one of documentInfo or documentReference must be provided"
        }
    }
}