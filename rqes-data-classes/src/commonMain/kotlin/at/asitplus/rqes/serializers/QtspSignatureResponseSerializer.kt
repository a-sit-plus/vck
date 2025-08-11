package at.asitplus.rqes.serializers

import at.asitplus.rqes.QtspSignatureResponse
import at.asitplus.rqes.SignDocResponseParameters
import at.asitplus.rqes.SignHashResponseParameters
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject


@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.csc.serializers.QtspSignatureResponseSerializer"))
object QtspSignatureResponseSerializer :
    JsonContentPolymorphicSerializer<QtspSignatureResponse>(QtspSignatureResponse::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<QtspSignatureResponse> = when {
        "DocumentWithSignature" in element.jsonObject
                || "SignatureObject" in element.jsonObject
                || "validationInfo" in element.jsonObject -> SignDocResponseParameters.serializer()
        else -> SignHashResponseParameters.serializer()
    }
}