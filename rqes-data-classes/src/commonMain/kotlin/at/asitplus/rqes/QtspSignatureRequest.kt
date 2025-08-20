package at.asitplus.rqes

import at.asitplus.rqes.enums.OperationMode
import at.asitplus.rqes.serializers.QtspSignatureRequestSerializer
import kotlinx.serialization.Serializable

@Serializable(with = QtspSignatureRequestSerializer::class)
@Deprecated(
    "Module will be removed in the future", ReplaceWith(
        "QtspSignatureRequest",
        imports = ["at.asitplus.csc.QtspSignatureRequest"]
    )
)
sealed interface QtspSignatureRequest {
    val credentialId: String?
    val sad: String?
    val operationMode: OperationMode?
    val validityPeriod: Int?
    val responseUri: String?
    val clientData: String?
}
