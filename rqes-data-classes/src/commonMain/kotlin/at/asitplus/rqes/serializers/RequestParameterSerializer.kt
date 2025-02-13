package at.asitplus.rqes.serializers

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.rqes.SignatureRequestParameters
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object RequestParametersSerializer : JsonContentPolymorphicSerializer<RequestParameters>(RequestParameters::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<RequestParameters> {
        val parameters = element.jsonObject
        return when {
            "documentDigests" in parameters -> SignatureRequestParameters.serializer()
            else -> AuthenticationRequestParameters.serializer()
        }
    }
}
