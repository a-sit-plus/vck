package at.asitplus.rqes

import at.asitplus.rqes.enums.OperationMode
import at.asitplus.rqes.serializers.QtspSignatureRequestSerializer
import kotlinx.serialization.Serializable

@Deprecated("Renamed", ReplaceWith("QtspSignatureRequest"))
typealias CscSignatureRequest = QtspSignatureRequest

@Serializable(with = QtspSignatureRequestSerializer::class)
sealed interface QtspSignatureRequest {
    val credentialId: String?
    val sad: String?
    val operationMode: OperationMode?
    val validityPeriod: Int?
    val responseUri: String?
    val clientData: String?
}
