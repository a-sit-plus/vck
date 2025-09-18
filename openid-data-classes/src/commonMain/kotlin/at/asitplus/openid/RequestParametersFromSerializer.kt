package at.asitplus.openid

import at.asitplus.dcapi.request.DCAPIRequest
import at.asitplus.dcapi.request.Oid4vpDCAPIRequest
import at.asitplus.openid.RequestParametersFrom.SerialNames.DC_API_REQUEST
import at.asitplus.openid.RequestParametersFrom.SerialNames.JSON_STRING
import at.asitplus.openid.RequestParametersFrom.SerialNames.JWS_SIGNED
import at.asitplus.openid.RequestParametersFrom.SerialNames.PARAMETERS
import at.asitplus.openid.RequestParametersFrom.SerialNames.TYPE_JSON
import at.asitplus.openid.RequestParametersFrom.SerialNames.TYPE_JWS_SIGNED
import at.asitplus.openid.RequestParametersFrom.SerialNames.TYPE_URI
import at.asitplus.openid.RequestParametersFrom.SerialNames.URL
import at.asitplus.openid.RequestParametersFrom.SerialNames.VERIFIED
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
    val dcApiRequestSerializer = Oid4vpDCAPIRequest.serializer()
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("RequestParametersFromClass") {
        element(TYPE_JSON, buildClassSerialDescriptor(TYPE_JSON) {
            element<String>(JSON_STRING)
            element(PARAMETERS, parameterSerializer.descriptor)
            element(DC_API_REQUEST, dcApiRequestSerializer.descriptor)
        })
        element(TYPE_JWS_SIGNED, buildClassSerialDescriptor(TYPE_JWS_SIGNED) {
            element(JWS_SIGNED, JwsSignedSerializer.descriptor)
            element(PARAMETERS, parameterSerializer.descriptor)
            element<Boolean>(VERIFIED)
            element(DC_API_REQUEST, dcApiRequestSerializer.descriptor)
        })
        element(TYPE_URI, buildClassSerialDescriptor(TYPE_URI) {
            element(URL, UrlSerializer.descriptor)
            element(PARAMETERS, parameterSerializer.descriptor)
        })
    }

    override fun deserialize(decoder: Decoder): RequestParametersFrom<T> {
        require(decoder is JsonDecoder) // this class can be decoded only by Json

        val element = decoder.decodeJsonElement()
        return when {
            JWS_SIGNED in element.jsonObject && DC_API_REQUEST in element.jsonObject -> run {
                val dcApiRequest =
                    decoder.json.decodeFromJsonElement(dcApiRequestSerializer, element.jsonObject[DC_API_REQUEST]!!)
                val parameters =
                    decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject[PARAMETERS]!!)
                val jwsString = decoder.json.decodeFromJsonElement<String>(element.jsonObject[JWS_SIGNED]!!)
                val jwsGeneric = JwsSigned.deserialize(jwsString).getOrThrow()
                RequestParametersFrom.DcApiSigned(
                    dcApiRequest,
                    parameters,
                    JwsSigned<T>(jwsGeneric.header, parameters, jwsGeneric.signature, jwsGeneric.plainSignatureInput),
                )
            }

            JSON_STRING in element.jsonObject && DC_API_REQUEST in element.jsonObject -> RequestParametersFrom.DcApiUnsigned(
                decoder.json.decodeFromJsonElement(dcApiRequestSerializer, element.jsonObject[DC_API_REQUEST]!!),
                decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject[PARAMETERS]!!),
                decoder.json.decodeFromJsonElement<String>(element.jsonObject[JSON_STRING]!!),
            )

            JSON_STRING in element.jsonObject && DC_API_REQUEST !in element.jsonObject -> RequestParametersFrom.Json(
                decoder.json.decodeFromJsonElement<String>(element.jsonObject[JSON_STRING]!!),
                decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject[PARAMETERS]!!),
            )

            JWS_SIGNED in element.jsonObject && DC_API_REQUEST !in element.jsonObject -> run {
                val parameters =
                    decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject[PARAMETERS]!!)
                val jwsString = decoder.json.decodeFromJsonElement<String>(element.jsonObject[JWS_SIGNED]!!)
                val jwsGeneric = JwsSigned.deserialize(jwsString).getOrThrow()
                val verified = element.jsonObject[VERIFIED]?.let { decoder.json.decodeFromJsonElement<Boolean>(it) }
                    ?: false

                RequestParametersFrom.JwsSigned(
                    JwsSigned<T>(jwsGeneric.header, parameters, jwsGeneric.signature, jwsGeneric.plainSignatureInput),
                    parameters,
                    verified,
                )
            }

            URL in element.jsonObject -> RequestParametersFrom.Uri(
                decoder.json.decodeFromJsonElement(UrlSerializer, element.jsonObject[URL]!!),
                decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject[PARAMETERS]!!)
            )

            else -> throw NotImplementedError("Unknown RequestParametersFrom subclass. Input: $element")
        }
    }

    override fun serialize(encoder: Encoder, value: RequestParametersFrom<T>) {
        require(encoder is JsonEncoder) // this class can be decoded only by Json
        val element = when (value) {
            is RequestParametersFrom.Json -> buildJsonObject {
                put(JSON_STRING, encoder.json.encodeToJsonElement(value.jsonString))
                put(PARAMETERS, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
            }

            is RequestParametersFrom.JwsSigned -> buildJsonObject {
                put(JWS_SIGNED, encoder.json.encodeToJsonElement(value.jwsSigned.serialize()))
                put(PARAMETERS, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
                put(VERIFIED, encoder.json.encodeToJsonElement(value.verified))
            }

            is RequestParametersFrom.Uri -> buildJsonObject {
                put(URL, encoder.json.encodeToJsonElement(UrlSerializer, value.url))
                put(PARAMETERS, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
            }

            is RequestParametersFrom.DcApiSigned<*> -> buildJsonObject {
                put(DC_API_REQUEST, encoder.json.encodeToJsonElement(dcApiRequestSerializer, value.dcApiRequest))
                put(JWS_SIGNED, encoder.json.encodeToJsonElement(value.jwsSigned.serialize()))
                put(PARAMETERS, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
            }

            is RequestParametersFrom.DcApiUnsigned<*> -> buildJsonObject {
                put(DC_API_REQUEST, encoder.json.encodeToJsonElement(dcApiRequestSerializer, value.dcApiRequest))
                put(JSON_STRING, encoder.json.encodeToJsonElement(value.jsonString))
                put(PARAMETERS, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
            }
        }
        encoder.encodeJsonElement(element)
    }
}