package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JwsSigned
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

/**
 * In order to de-/serialize generic types we need a kind of factory approach
 * Because we deal with a sealed class we can use an intermediary jsonSerializer,
 * find the correct object and the specific type of the generic type and
 * then finalize the serialization
 *
 * In order to de-/serialize JwsSigned which itself is again a generic class
 * we use the fact that we can find the class of parameters before we need to know the
 * generic class of JwsSigned. To serialize we use [JwsSignedSerializer].
 */
class RequestParametersFromSerializer<T : RequestParameters>(
    private val parameterSerializer: KSerializer<T>,
) : KSerializer<RequestParametersFrom<T>> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("RequestParametersFromClass") {
        element("Json", buildClassSerialDescriptor("Json") {
            element<String>("jsonString")
            element("parameters", parameterSerializer.descriptor)
        })
        element("JwsSigned", buildClassSerialDescriptor("JwsSigned") {
            element("jwsSigned", JwsSignedSerializer.descriptor)
            element("parameters", parameterSerializer.descriptor)
        })
        element("Url", buildClassSerialDescriptor("Url") {
            element("url", UrlSerializer.descriptor)
            element("parameters", parameterSerializer.descriptor)
        })
    }

    override fun deserialize(decoder: Decoder): RequestParametersFrom<T> {
        require(decoder is JsonDecoder) // this class can be decoded only by Json

        val element = decoder.decodeJsonElement()
        return when {
            "jsonString" in element.jsonObject -> RequestParametersFrom.Json(
                decoder.json.decodeFromJsonElement<String>(element.jsonObject["jsonString"]!!),
                decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject["parameters"]!!)
            )

            "jwsSigned" in element.jsonObject -> run {
                val parameters =
                    decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject["parameters"]!!)
                val jwsSignedRaw = decoder.json.decodeFromJsonElement<String>(element.jsonObject["jwsSigned"]!!)
                val jwsSignedFinal1 = JwsSigned.deserialize(jwsSignedRaw).getOrThrow()
                val jws = JwsSigned<T>(
                    jwsSignedFinal1.header,
                    parameters,
                    jwsSignedFinal1.signature,
                    jwsSignedFinal1.plainSignatureInput
                )
                RequestParametersFrom.JwsSigned(
                    jws,
                    parameters,
                )
            }

            "url" in element.jsonObject ->
                RequestParametersFrom.Uri(
                    decoder.json.decodeFromJsonElement(UrlSerializer, element.jsonObject["url"]!!),
                    decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject["parameters"]!!)
                )

            else -> throw NotImplementedError("Unknown RequestParametersFrom subclass. Input: $element")
        }
    }

    override fun serialize(encoder: Encoder, value: RequestParametersFrom<T>) {
        require(encoder is JsonEncoder) // this class can be decoded only by Json
        val element = when (value) {
            is RequestParametersFrom.Json -> buildJsonObject {
                put("jsonString", encoder.json.encodeToJsonElement(value.jsonString))
                put(
                    "parameters", encoder.json.encodeToJsonElement(
                        parameterSerializer,
                        value.parameters
                    )
                )
            }

            is RequestParametersFrom.JwsSigned -> buildJsonObject {
                put("jwsSigned", encoder.json.encodeToJsonElement(value.jwsSigned.serialize()))
                put(
                    "parameters", encoder.json.encodeToJsonElement(
                        parameterSerializer,
                        value.parameters
                    )
                )
            }

            is RequestParametersFrom.Uri -> buildJsonObject {
                put("url", encoder.json.encodeToJsonElement(UrlSerializer, value.url))
                put(
                    "parameters", encoder.json.encodeToJsonElement(
                        parameterSerializer,
                        value.parameters
                    )
                )
            }
        }
        encoder.encodeJsonElement(element)
    }
}