package at.asitplus.csc.api.serializers

import at.asitplus.csc.api.QtspSignatureRequest
import at.asitplus.csc.api.SignDocRequestParameters
import at.asitplus.csc.api.SignHashRequestParameters
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