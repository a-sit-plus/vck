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
    /** Selects the concrete request type before interpreting form values, preserving opaque string parameters. */
    fun decodeFormParameters(parameters: FormParameters): RequestParameters =
        parameters.decode(selectDeserializer(parameters.keys))

    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<RequestParameters> =
        selectDeserializer(element.jsonObject.keys)

    private fun selectDeserializer(parameterNames: Set<String>): DeserializationStrategy<RequestParameters> = when {
        "deviceRequest" in parameterNames -> RequestParametersFrom.IsoMdocDcApi.IsoMdocRequestWrapper.serializer()
        "documentDigests" in parameterNames -> SignatureRequestParameters.serializer()
        ("request" in parameterNames) || ("request_uri" in parameterNames) -> JarRequestParameters.serializer()
        else -> AuthenticationRequestParameters.serializer()
    }
}
