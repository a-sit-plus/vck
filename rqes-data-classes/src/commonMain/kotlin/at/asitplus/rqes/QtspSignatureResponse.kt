package at.asitplus.rqes

import at.asitplus.rqes.serializers.QtspSignatureResponseSerializer
import kotlinx.serialization.Serializable

@Deprecated("Renamed", ReplaceWith("QtspSignatureResponse"))
typealias SignatureResponse = QtspSignatureResponse

@Serializable(with = QtspSignatureResponseSerializer::class)
sealed interface QtspSignatureResponse
