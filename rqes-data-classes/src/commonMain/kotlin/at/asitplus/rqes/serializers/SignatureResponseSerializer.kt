package at.asitplus.rqes.serializers

import at.asitplus.rqes.SignatureResponse
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object SignatureResponseSerializer : JsonContentPolymorphicSerializer<SignatureResponse>(SignatureResponse::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<SignatureResponse> = when {
        "DocumentWithSignature" in element.jsonObject || "SignatureObject" in element.jsonObject || "validationInfo" in element.jsonObject -> SignatureResponse.SignDocResponse.serializer()
        else -> SignatureResponse.SignHashResponse.serializer()
    }
}