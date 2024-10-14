package at.asitplus.dif.rqes.serializers

import at.asitplus.dif.rqes.SignDocParameters
import at.asitplus.dif.rqes.SignHashParameters
import at.asitplus.dif.rqes.SignatureRequestParameters
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object SignatureRequestParameterSerializer :
    JsonContentPolymorphicSerializer<SignatureRequestParameters>(SignatureRequestParameters::class) {
    override fun selectDeserializer(element: JsonElement) = when {
        "hashes" in element.jsonObject -> SignHashParameters.serializer()
        else -> SignDocParameters.serializer()
    }
}