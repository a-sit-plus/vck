package at.asitplus.openid

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

/**
 * TODO [RequestObjectParameters] can never be serialized into!
 * (needs non-nullable field in either [AuthenticationRequestParameters] or [RequestObjectParameters])
 */
object RequestParametersSerializer : JsonContentPolymorphicSerializer<RequestParameters>(RequestParameters::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<RequestParameters> {
        val parameters = element.jsonObject
        return when {
            "documentDigests" in parameters -> SignatureRequestParameters.serializer()
            else -> AuthenticationRequestParameters.serializer()
        }
    }
}
