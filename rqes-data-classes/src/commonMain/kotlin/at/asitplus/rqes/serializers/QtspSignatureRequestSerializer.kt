package at.asitplus.rqes.serializers

import at.asitplus.rqes.QtspSignatureRequest
import at.asitplus.rqes.SignDocRequestParameters
import at.asitplus.rqes.SignHashRequestParameters
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.csc.serializers.QtspSignatureRequestSerializer"))
object QtspSignatureRequestSerializer :
    JsonContentPolymorphicSerializer<QtspSignatureRequest>(QtspSignatureRequest::class) {
    override fun selectDeserializer(element: JsonElement) = when {
        "hashes" in element.jsonObject -> SignHashRequestParameters.serializer()
        else -> SignDocRequestParameters.serializer()
    }
}