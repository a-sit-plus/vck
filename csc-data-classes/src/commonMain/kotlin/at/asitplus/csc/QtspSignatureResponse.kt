package at.asitplus.csc

import at.asitplus.csc.serializers.QtspSignatureResponseSerializer
import kotlinx.serialization.Serializable

@Serializable(with = QtspSignatureResponseSerializer::class)
sealed interface QtspSignatureResponse
