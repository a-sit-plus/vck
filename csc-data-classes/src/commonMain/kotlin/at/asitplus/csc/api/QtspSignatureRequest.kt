package at.asitplus.csc.api

import at.asitplus.csc.api.serializers.QtspSignatureRequestSerializer
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
