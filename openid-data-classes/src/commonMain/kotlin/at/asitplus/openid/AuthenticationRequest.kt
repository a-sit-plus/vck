package at.asitplus.openid

import io.ktor.http.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
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

class RequestParametersFromClassSerializer<T : RequestParameters>(
    private val parameterSerializer: KSerializer<T>,
) : KSerializer<RequestParametersFromClass<T>> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("RequestParametersFromClass") {
        element("JwsSigned", parameterSerializer.descriptor)
        element("Json", buildClassSerialDescriptor("Json") {
            element<String>("jsonString")
            element("parameters", parameterSerializer.descriptor)
        })
        element("Uri", parameterSerializer.descriptor)
    }

    override fun deserialize(decoder: Decoder): RequestParametersFromClass<T> {
        // Decoder -> JsonDecoder
        require(decoder is JsonDecoder) // this class can be decoded only by Json
        // JsonDecoder -> JsonElement
        val element = decoder.decodeJsonElement()
        return when {
            "jsonString" in element.jsonObject -> RequestParametersFromClass.Json(
                decoder.json.decodeFromJsonElement<String>(element.jsonObject["jsonString"]!!),
                decoder.json.decodeFromJsonElement(parameterSerializer, element.jsonObject["parameters"]!!)
            )

            else -> TODO()
        }
    }

    override fun serialize(encoder: Encoder, value: RequestParametersFromClass<T>) {
        // Encoder -> JsonEncoder
        require(encoder is JsonEncoder) // This class can be encoded only by Json
        // value -> JsonElement
        val element = when (value) {
            is RequestParametersFromClass.Json -> buildJsonObject {
                put("jsonString", encoder.json.encodeToJsonElement(value.jsonString))
                put(
                    "parameters", encoder.json.encodeToJsonElement(
                        parameterSerializer,
                        value.parameters
                    )
                )
            }

            else -> TODO()
        }
        // JsonElement -> JsonEncoder
        encoder.encodeJsonElement(element)
    }
}


@Serializable(with = RequestParametersFromClassSerializer::class)
sealed class RequestParametersFromClass<S : RequestParameters> {

    abstract val parameters: S

    @Serializable
    @SerialName("JwsSigned")
    data class JwsSigned<T : RequestParameters>(
        @Serializable(JwsSignedSerializer::class)
        val jwsSigned: at.asitplus.signum.indispensable.josef.JwsSigned<T>,
        override val parameters: T,
    ) : RequestParametersFromClass<T>() {

    }

    @Serializable
    @SerialName("Uri")
    data class Uri<T : RequestParameters>(
        @Serializable(UrlSerializer::class)
        val url: Url,
        override val parameters: T,
    ) : RequestParametersFromClass<T>() {

//        override inline fun serialize(json: kotlinx.serialization.json.Json): String = json.encodeToString(this)
    }

    @Serializable
    @SerialName("Json")
    data class Json<T : RequestParameters>(
        val jsonString: String,
        override val parameters: T,
    ) : RequestParametersFromClass<T>() {

//        override fun serialize(json: kotlinx.serialization.json.Json): String = json.encodeToString(this)
    }

//    companion object {
//        inline fun <P : RequestParameters> deserialize(
//            it: String,
//            json: kotlinx.serialization.json.Json = kotlinx.serialization.json.Json,
//        ): KmmResult<RequestParametersFromClass<P>> =
//            catching { json.decodeFromString<RequestParametersFromClass<P>>(it) }
//    }
}


