package at.asitplus.rqes.serializers

import at.asitplus.rqes.RequestParameters
import at.asitplus.rqes.SignatureRequestParameters
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement


@Deprecated(
    "Module will be removed in the future", ReplaceWith(
        "RequestParameterSerializer",
        imports = ["at.asitplus.openid.RequestParameterSerializer"]
    )
)
object RequestParametersSerializer : JsonContentPolymorphicSerializer<RequestParameters>(RequestParameters::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<RequestParameters> =
        SignatureRequestParameters.serializer()
}
