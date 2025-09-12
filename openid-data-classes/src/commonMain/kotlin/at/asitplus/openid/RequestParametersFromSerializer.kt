package at.asitplus.openid

import at.asitplus.dcapi.request.DCAPIRequest
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

private const val JwsSignedSerialName = "JwsSigned"
private const val JsonSerialName = "Json"
private const val UriSerialName = "Uri"

private const val JwsSignedElementName = "jwsSigned"
private const val JsonElementName = "jsonString"
private const val UriElementName = "url"
private const val ParametersElementName = "parameters"
private const val DcApiRequestElementName = "dcApiRequest"
private const val VerifiedElementName = "verified"

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
    val dcApiRequestSerializer = DCAPIRequest.serializer()
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("RequestParametersFromClass") {
        element(JsonSerialName, buildClassSerialDescriptor(JsonSerialName) {
            element<String>(JsonElementName)
            element(ParametersElementName, parameterSerializer.descriptor)
            element(DcApiRequestElementName, dcApiRequestSerializer.descriptor)
        })
        element(JwsSignedSerialName, buildClassSerialDescriptor(JwsSignedSerialName) {
            element(JwsSignedElementName, JwsSignedSerializer.descriptor)
            element(ParametersElementName, parameterSerializer.descriptor)
            element<Boolean>(VerifiedElementName)
            element(DcApiRequestElementName, dcApiRequestSerializer.descriptor)
        })
        element(UriSerialName, buildClassSerialDescriptor(UriSerialName) {
            element(UriElementName, UrlSerializer.descriptor)
            element(ParametersElementName, parameterSerializer.descriptor)
        })
    }

    override fun deserialize(decoder: Decoder): RequestParametersFrom<T> {
        require(decoder is JsonDecoder) // this class can be decoded only by Json

        val element = decoder.decodeJsonElement()
        return when {
            JsonElementName in element.jsonObject -> RequestParametersFrom.Json(
                decoder.json.decodeFromJsonElement<String>(element.jsonObject[JsonElementName]!!),
                decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject[ParametersElementName]!!),
                element.jsonObject[DcApiRequestElementName]?.let { decoder.json.decodeFromJsonElement(dcApiRequestSerializer, it) }
            )

            JwsSignedElementName in element.jsonObject -> run {
                val parameters =
                    decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject[ParametersElementName]!!)
                val jwsString = decoder.json.decodeFromJsonElement<String>(element.jsonObject[JwsSignedElementName]!!)
                val verified = element.jsonObject[VerifiedElementName]?.let { decoder.json.decodeFromJsonElement<Boolean>(it) } ?: false
                val jwsGeneric = JwsSigned.deserialize(jwsString).getOrThrow()
                val dcApiRequest = element.jsonObject[DcApiRequestElementName]?.let { decoder.json.decodeFromJsonElement(dcApiRequestSerializer, it) }


                RequestParametersFrom.JwsSigned(
                    JwsSigned<T>(jwsGeneric.header, parameters, jwsGeneric.signature, jwsGeneric.plainSignatureInput),
                    parameters,
                    verified,
                    dcApiRequest
                )
            }

            UriElementName in element.jsonObject -> RequestParametersFrom.Uri(
                decoder.json.decodeFromJsonElement(UrlSerializer, element.jsonObject[UriElementName]!!),
                decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject[ParametersElementName]!!)
            )

            else -> throw NotImplementedError("Unknown RequestParametersFrom subclass. Input: $element")
        }
    }

    override fun serialize(encoder: Encoder, value: RequestParametersFrom<T>) {
        require(encoder is JsonEncoder) // this class can be decoded only by Json
        val element = when (value) {
            is RequestParametersFrom.Json -> buildJsonObject {
                put(JsonElementName, encoder.json.encodeToJsonElement(value.jsonString))
                put(ParametersElementName, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
                value.dcApiRequest?.let { put(DcApiRequestElementName, encoder.json.encodeToJsonElement(DCAPIRequest.serializer(), it)) }
            }

            is RequestParametersFrom.JwsSigned -> buildJsonObject {
                put(JwsSignedElementName, encoder.json.encodeToJsonElement(value.jwsSigned.serialize()))
                put(ParametersElementName, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
                put(VerifiedElementName, encoder.json.encodeToJsonElement(value.verified))
                value.dcApiRequest?.let { put(DcApiRequestElementName, encoder.json.encodeToJsonElement(DCAPIRequest.serializer(), it)) }
            }

            is RequestParametersFrom.Uri -> buildJsonObject {
                put(UriElementName, encoder.json.encodeToJsonElement(UrlSerializer, value.url))
                put(ParametersElementName, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
            }
        }
        encoder.encodeJsonElement(element)
    }
}