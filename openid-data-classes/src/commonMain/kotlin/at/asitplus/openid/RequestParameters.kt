package at.asitplus.openid

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

sealed interface RequestParameters

object RequestParametersSerializer :
    JsonContentPolymorphicSerializer<RequestParameters>(RequestParameters::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<RequestParameters> {
        val parameters = element.jsonObject["parameters"]?.jsonObject
        return parameters?.let {
            when {
                "signatureQualifier" in it -> SignatureRequestParameters.serializer()
                else -> AuthenticationRequestParameters.serializer()
            }
        } ?: throw Exception("Invalid parameters")
    }
}


