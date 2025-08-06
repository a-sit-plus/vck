package at.asitplus.csc

import at.asitplus.csc.enums.OperationMode
import at.asitplus.csc.serializers.QtspSignatureRequestSerializer
import kotlinx.serialization.Serializable

@Serializable(with = QtspSignatureRequestSerializer::class)
sealed interface QtspSignatureRequest {
    val credentialId: String?
    val sad: String?
    val operationMode: OperationMode?
    val validityPeriod: Int?
    val responseUri: String?
    val clientData: String?
}
