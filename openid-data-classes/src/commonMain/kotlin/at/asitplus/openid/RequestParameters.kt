package at.asitplus.openid

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

@Serializable
sealed interface RequestParameters

object RequestParametersSerializer : JsonContentPolymorphicSerializer<RequestParameters>(RequestParameters::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<RequestParameters> {
        val parameters = element.jsonObject
        return when {
            "signatureQualifier" in parameters -> SignatureRequestParameters.serializer()
            else -> AuthenticationRequestParameters.serializer()
        }
    }
}


