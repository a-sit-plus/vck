package at.asitplus.rqes

import at.asitplus.rqes.enums.OperationMode
import at.asitplus.rqes.serializers.CscSignatureRequestParameterSerializer
import kotlinx.serialization.Serializable

@Serializable(with = CscSignatureRequestParameterSerializer::class)
sealed interface QtspSignatureRequest {
    val credentialId: String?
    val sad: String?
    val operationMode: OperationMode?
    val validityPeriod: Int?
    val responseUri: String?
    val clientData: String?
}
