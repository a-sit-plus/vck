package at.asitplus.openid

import at.asitplus.dcapi.request.DCAPIWalletRequest
import at.asitplus.openid.RequestParametersFrom.SerialNames.DC_API_REQUEST
import at.asitplus.openid.RequestParametersFrom.SerialNames.JSON_STRING
import at.asitplus.openid.RequestParametersFrom.SerialNames.JWS_COMPACT
import at.asitplus.openid.RequestParametersFrom.SerialNames.JWS_GENERAL
import at.asitplus.openid.RequestParametersFrom.SerialNames.PARAMETERS
import at.asitplus.openid.RequestParametersFrom.SerialNames.PARENT
import at.asitplus.openid.RequestParametersFrom.SerialNames.TYPE_DCAPI_MULTISIGNED
import at.asitplus.openid.RequestParametersFrom.SerialNames.TYPE_DCAPI_SIGNED
import at.asitplus.openid.RequestParametersFrom.SerialNames.TYPE_DCAPI_UNSIGNED
import at.asitplus.openid.RequestParametersFrom.SerialNames.TYPE_JSON
import at.asitplus.openid.RequestParametersFrom.SerialNames.TYPE_JWS_COMPACT
import at.asitplus.openid.RequestParametersFrom.SerialNames.TYPE_URI
import at.asitplus.openid.RequestParametersFrom.SerialNames.URL
import at.asitplus.openid.RequestParametersFrom.SerialNames.VERIFIED
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactStringSerializer
import at.asitplus.signum.indispensable.josef.JwsGeneral
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

/**
 * In order to de-/serialize generic types we need a kind of factory approach
 * Because we deal with a sealed class we can use an intermediary jsonSerializer,
 * find the correct object and the specific type of the generic type and
 * then finalize the serialization
 */
class RequestParametersFromSerializer<T : RequestParameters>(
    private val parameterSerializer: KSerializer<T>,
) : KSerializer<RequestParametersFrom<T>> {
    private val signedDcApiRequestSerializer = DCAPIWalletRequest.OpenId4VpSigned.serializer()
    private val multisignedDcApiRequestSerializer = DCAPIWalletRequest.OpenId4VpMultiSigned.serializer()
    private val unsignedDcApiRequestSerializer = DCAPIWalletRequest.OpenId4VpUnsigned.serializer()

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("RequestParametersFrom") {
        element(TYPE_JWS_COMPACT, buildClassSerialDescriptor(TYPE_JWS_COMPACT) {
            element(JWS_COMPACT, JwsCompactStringSerializer.descriptor)
            element(PARAMETERS, parameterSerializer.descriptor)
            element<Boolean>(VERIFIED)
            element(PARENT, UrlSerializer.descriptor)
        })
        element(TYPE_DCAPI_SIGNED, buildClassSerialDescriptor(TYPE_DCAPI_SIGNED) {
            element(DC_API_REQUEST, signedDcApiRequestSerializer.descriptor)
            element(PARAMETERS, parameterSerializer.descriptor)
            element(JWS_COMPACT, JwsCompactStringSerializer.descriptor)
        })
        element(TYPE_DCAPI_MULTISIGNED, buildClassSerialDescriptor(TYPE_DCAPI_MULTISIGNED) {
            element(DC_API_REQUEST, multisignedDcApiRequestSerializer.descriptor)
            element(PARAMETERS, parameterSerializer.descriptor)
            element(JWS_GENERAL, JwsGeneral.serializer().descriptor)
        })
        element(TYPE_DCAPI_UNSIGNED, buildClassSerialDescriptor(TYPE_DCAPI_UNSIGNED) {
            element(DC_API_REQUEST, unsignedDcApiRequestSerializer.descriptor)
            element(PARAMETERS, parameterSerializer.descriptor)
            element<String>(JSON_STRING)
        })
        element(TYPE_URI, buildClassSerialDescriptor(TYPE_URI) {
            element(URL, UrlSerializer.descriptor)
            element(PARAMETERS, parameterSerializer.descriptor)
        })
        element(TYPE_JSON, buildClassSerialDescriptor(TYPE_JSON) {
            element<String>(JSON_STRING)
            element(PARAMETERS, parameterSerializer.descriptor)
            element(PARENT, UrlSerializer.descriptor)
        })
    }

    override fun deserialize(decoder: Decoder): RequestParametersFrom<T> {
        require(decoder is JsonDecoder) // this class can be decoded only by Json

        val element = decoder.decodeJsonElement()
        val parameters = decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject[PARAMETERS]!!)
        return when {
            JWS_GENERAL in element.jsonObject && DC_API_REQUEST in element.jsonObject ->
                RequestParametersFrom.DcApiMultiSigned(
                    dcApiRequest = decoder.json.decodeFromJsonElement(
                        multisignedDcApiRequestSerializer,
                        element.jsonObject[DC_API_REQUEST]!!
                    ),
                    parameters = parameters,
                    jws = decoder.json.decodeFromJsonElement(element.jsonObject[JWS_GENERAL]!!)
                )

            JWS_COMPACT in element.jsonObject && DC_API_REQUEST in element.jsonObject ->
                RequestParametersFrom.DcApiSigned(
                    dcApiRequest = decoder.json.decodeFromJsonElement(
                        signedDcApiRequestSerializer,
                        element.jsonObject[DC_API_REQUEST]!!
                    ),
                    parameters = parameters,
                    jws = decoder.json.decodeFromJsonElement(JwsCompactStringSerializer,element.jsonObject[JWS_COMPACT]!!)
                )

            JSON_STRING in element.jsonObject && DC_API_REQUEST in element.jsonObject ->
                RequestParametersFrom.DcApiUnsigned(
                    dcApiRequest = decoder.json.decodeFromJsonElement(
                        unsignedDcApiRequestSerializer,
                        element.jsonObject[DC_API_REQUEST]!!
                    ),
                    parameters = parameters,
                    jsonString = decoder.json.decodeFromJsonElement<String>(element.jsonObject[JSON_STRING]!!),
                )

            JSON_STRING in element.jsonObject && DC_API_REQUEST !in element.jsonObject ->
                RequestParametersFrom.Json(
                    jsonString = decoder.json.decodeFromJsonElement<String>(element.jsonObject[JSON_STRING]!!),
                    parameters = parameters,
                    parent = element.jsonObject[PARENT]?.takeIf { it !is JsonNull }?.let {
                        decoder.json.decodeFromJsonElement(UrlSerializer, it)
                    },
                )

            JWS_COMPACT in element.jsonObject && DC_API_REQUEST !in element.jsonObject ->
                RequestParametersFrom.JwsCompact(
                    jws = JwsCompact(decoder.json.decodeFromJsonElement<String>(element.jsonObject[JWS_COMPACT]!!)),
                    parameters = parameters,
                    verified = element.jsonObject[VERIFIED]?.let { decoder.json.decodeFromJsonElement(it) }
                        ?: false,
                    parent = element.jsonObject[PARENT]?.takeIf { it !is JsonNull }?.let {
                        decoder.json.decodeFromJsonElement(UrlSerializer, it)
                    },
                )

            URL in element.jsonObject ->
                RequestParametersFrom.Uri(
                    url = decoder.json.decodeFromJsonElement(UrlSerializer, element.jsonObject[URL]!!),
                    parameters = parameters
                )

            else -> throw NotImplementedError("Unknown RequestParametersFrom subclass. Input: $element")
        }
    }

    override fun serialize(encoder: Encoder, value: RequestParametersFrom<T>) {
        require(encoder is JsonEncoder) // this class can be decoded only by Json
        val element = when (value) {
            is RequestParametersFrom.JwsCompact -> buildJsonObject {
                put(JWS_COMPACT, encoder.json.encodeToJsonElement(JwsCompactStringSerializer, value.jws))
                put(PARAMETERS, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
                put(VERIFIED, encoder.json.encodeToJsonElement(value.verified))
                value.parent?.let { put(PARENT, encoder.json.encodeToJsonElement(it)) }
            }

            is RequestParametersFrom.DcApiMultiSigned<*> -> buildJsonObject {
                put(
                    DC_API_REQUEST,
                    encoder.json.encodeToJsonElement(multisignedDcApiRequestSerializer, value.dcApiRequest)
                )
                put(PARAMETERS, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
                put(JWS_GENERAL, encoder.json.encodeToJsonElement(value.jws))
            }

            is RequestParametersFrom.DcApiSigned<*> -> buildJsonObject {
                put(DC_API_REQUEST, encoder.json.encodeToJsonElement(signedDcApiRequestSerializer, value.dcApiRequest))
                put(PARAMETERS, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
                put(JWS_COMPACT, encoder.json.encodeToJsonElement(JwsCompactStringSerializer, value.jws))
            }

            is RequestParametersFrom.DcApiUnsigned<*> -> buildJsonObject {
                put(
                    DC_API_REQUEST,
                    encoder.json.encodeToJsonElement(unsignedDcApiRequestSerializer, value.dcApiRequest)
                )
                put(PARAMETERS, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
                put(JSON_STRING, encoder.json.encodeToJsonElement(value.jsonString))
            }

            is RequestParametersFrom.Uri -> buildJsonObject {
                put(URL, encoder.json.encodeToJsonElement(UrlSerializer, value.url))
                put(PARAMETERS, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
            }

            is RequestParametersFrom.Json -> buildJsonObject {
                put(JSON_STRING, encoder.json.encodeToJsonElement(value.jsonString))
                put(PARAMETERS, encoder.json.encodeToJsonElement(parameterSerializer, value.parameters))
                value.parent?.let { put(PARENT, encoder.json.encodeToJsonElement(it)) }
            }
        }
        encoder.encodeJsonElement(element)
    }
}