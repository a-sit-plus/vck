package at.asitplus.wallet.lib.oidc

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

sealed interface RequestParametersFrom

object RequestParametersFromSerializer :
    JsonContentPolymorphicSerializer<RequestParametersFrom>(RequestParametersFrom::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<RequestParametersFrom> {
        val parameters = element.jsonObject["parameters"]?.jsonObject
        return parameters?.let {
            when {
                "signatureQualifier" in it -> SignatureRequestParametersFrom.serializer()
                else -> AuthenticationRequestParametersFrom.serializer()
            }
        } ?: throw Exception("Invalid parameters")
    }
}