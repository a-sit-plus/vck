package at.asitplus.csc.serializers

import at.asitplus.csc.QtspSignatureResponse
import at.asitplus.csc.SignDocResponseParameters
import at.asitplus.csc.SignHashResponseParameters
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object QtspSignatureResponseSerializer :
    JsonContentPolymorphicSerializer<QtspSignatureResponse>(QtspSignatureResponse::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<QtspSignatureResponse> = when {
        "DocumentWithSignature" in element.jsonObject
                || "SignatureObject" in element.jsonObject
                || "validationInfo" in element.jsonObject -> SignDocResponseParameters.serializer()
        else -> SignHashResponseParameters.serializer()
    }
}