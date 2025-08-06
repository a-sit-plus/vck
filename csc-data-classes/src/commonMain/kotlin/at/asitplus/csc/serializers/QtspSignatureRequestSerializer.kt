package at.asitplus.csc.serializers

import at.asitplus.csc.QtspSignatureRequest
import at.asitplus.csc.SignDocRequestParameters
import at.asitplus.csc.SignHashRequestParameters
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object QtspSignatureRequestSerializer :
    JsonContentPolymorphicSerializer<QtspSignatureRequest>(QtspSignatureRequest::class) {
    override fun selectDeserializer(element: JsonElement) = when {
        "hashes" in element.jsonObject -> SignHashRequestParameters.serializer()
        else -> SignDocRequestParameters.serializer()
    }
}