package at.asitplus.rqes

import at.asitplus.rqes.serializers.QtspSignatureResponseSerializer
import kotlinx.serialization.Serializable

@Serializable(with = QtspSignatureResponseSerializer::class)
@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.csc.QtspSignatureResponse"))
sealed interface QtspSignatureResponse
