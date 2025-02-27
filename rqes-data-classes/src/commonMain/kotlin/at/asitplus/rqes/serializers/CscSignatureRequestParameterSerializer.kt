package at.asitplus.rqes.serializers

import at.asitplus.rqes.QtspSignatureRequest
import at.asitplus.rqes.SignDocParameters
import at.asitplus.rqes.SignHashParameters
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object CscSignatureRequestParameterSerializer :
    JsonContentPolymorphicSerializer<QtspSignatureRequest>(QtspSignatureRequest::class) {
    override fun selectDeserializer(element: JsonElement) = when {
        "hashes" in element.jsonObject -> SignHashParameters.serializer()
        else -> SignDocParameters.serializer()
    }
}