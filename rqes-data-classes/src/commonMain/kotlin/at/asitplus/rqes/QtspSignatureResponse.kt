package at.asitplus.rqes

import at.asitplus.rqes.serializers.QtspSignatureResponseSerializer
import kotlinx.serialization.Serializable


@Serializable(with = QtspSignatureResponseSerializer::class)
sealed interface QtspSignatureResponse
