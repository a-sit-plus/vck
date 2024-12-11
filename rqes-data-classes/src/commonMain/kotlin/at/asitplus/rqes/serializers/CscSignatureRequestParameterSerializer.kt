package at.asitplus.rqes.serializers

import at.asitplus.rqes.CscSignatureRequestParameters
import at.asitplus.rqes.SignDocParameters
import at.asitplus.rqes.SignHashParameters
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object CscSignatureRequestParameterSerializer :
    JsonContentPolymorphicSerializer<CscSignatureRequestParameters>(CscSignatureRequestParameters::class) {
    override fun selectDeserializer(element: JsonElement) = when {
        "hashes" in element.jsonObject -> SignHashParameters.serializer()
        else -> SignDocParameters.serializer()
    }
}