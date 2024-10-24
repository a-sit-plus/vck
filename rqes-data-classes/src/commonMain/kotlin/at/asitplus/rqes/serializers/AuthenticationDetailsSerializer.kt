package at.asitplus.rqes.serializers

import CscAuthorizationDetails
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object AuthorizationDetailsSerializer :
    JsonContentPolymorphicSerializer<AuthorizationDetails>(AuthorizationDetails::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<AuthorizationDetails> {
        val parameters = element.jsonObject
        return when {
            "documentDigests" in parameters -> CscAuthorizationDetails.serializer()
            else -> OpenIdAuthorizationDetails.serializer()
        }
    }
}
