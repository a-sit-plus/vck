package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.RequestParameters
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

@Serializable
sealed interface RequestParametersFrom {
    val parameters: RequestParameters
}

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