package at.asitplus.rqes.serializers

import at.asitplus.dif.rqes.CSCSignatureRequestParameters
import at.asitplus.dif.rqes.SignDocParameters
import at.asitplus.dif.rqes.SignHashParameters
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object CSCSignatureRequestParameterSerializer :
    JsonContentPolymorphicSerializer<CSCSignatureRequestParameters>(CSCSignatureRequestParameters::class) {
    override fun selectDeserializer(element: JsonElement) = when {
        "hashes" in element.jsonObject -> SignHashParameters.serializer()
        else -> SignDocParameters.serializer()
    }
}