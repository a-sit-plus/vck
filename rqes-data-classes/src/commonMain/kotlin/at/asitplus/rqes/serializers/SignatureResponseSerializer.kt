package at.asitplus.rqes.serializers

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.InputDescriptor
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.rqes.SignatureResponse
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object SignatureResponseSerializer : JsonContentPolymorphicSerializer<SignatureResponse>(SignatureResponse::class) {
    override fun selectDeserializer(element: JsonElement) = when {
        "DocumentWithSignature" in element.jsonObject || "SignatureObject" in element.jsonObject || "validationInfo" in element.jsonObject -> SignatureResponse.SignDocResponse.serializer()
        else -> SignatureResponse.SignHashResponse.serializer()
    }
}