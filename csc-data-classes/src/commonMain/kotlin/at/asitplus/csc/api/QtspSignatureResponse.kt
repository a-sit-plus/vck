package at.asitplus.csc.api

import at.asitplus.csc.api.serializers.QtspSignatureResponseSerializer
import kotlinx.serialization.Serializable

@Serializable(with = QtspSignatureResponseSerializer::class)
sealed interface QtspSignatureResponse
