package at.asitplus.openid

import at.asitplus.openid.RequestParametersFrom.SerialNames.DC_API_REQUEST
import at.asitplus.openid.RequestParametersFrom.SerialNames.JSON_STRING
import at.asitplus.openid.RequestParametersFrom.SerialNames.JWS_SIGNED
import at.asitplus.openid.RequestParametersFrom.SerialNames.PARAMETERS
import at.asitplus.openid.RequestParametersFrom.SerialNames.PARENT
import at.asitplus.openid.RequestParametersFrom.SerialNames.URL
import at.asitplus.openid.RequestParametersFrom.SerialNames.VERIFIED
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.ktor.http.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement

/**
 * In order to de-/serialize generic types we need a kind of factory approach
 * Because we deal with a sealed class we can use an intermediary surrogate,
 * keep the nested DC API request as a [JsonObject], determine the concrete
 * branch from the surrounding fields and then finalize the serialization.
 */
class RequestParametersFromSerializer<T : RequestParameters>(
    parameterSerializer: KSerializer<T>,
) : KSerializer<RequestParametersFrom<T>> by TransformingSerializerTemplate(
    parent = RequestParametersFromSurrogate.serializer(parameterSerializer),
    encodeAs = { RequestParametersFromSurrogate(it) },
    decodeAs = { it.toRequestParametersFrom() },
    serialName = "RequestParametersFrom",
)

@Serializable
private data class RequestParametersFromSurrogate<T : RequestParameters>(
    @SerialName(PARAMETERS)
    val parameters: T,
    @Serializable(JwsSignedSerializer::class)
    @SerialName(JWS_SIGNED)
    val jwsCompact: JwsSigned<T>? = null,
    @SerialName(JSON_STRING)
    val jsonString: String? = null,
    @Serializable(UrlSerializer::class)
    @SerialName(URL)
    val url: Url? = null,
    @Serializable(UrlSerializer::class)
    @SerialName(PARENT)
    val parent: Url? = null,
    @SerialName(DC_API_REQUEST)
    val dcApiRequest: JsonObject? = null,
    @SerialName(VERIFIED)
    val verified: Boolean? = null,
) {
    constructor(value: RequestParametersFrom<T>) : this(
        parameters = value.parameters,
        jwsCompact = when (value) {
            is RequestParametersFrom.JwsSigned -> value.jwsSigned
            else -> null
        },
        jsonString = when (value) {
            is RequestParametersFrom.DcApiUnsigned<*> -> value.jsonString
            is RequestParametersFrom.Json -> value.jsonString
            else -> null
        },
        url = (value as? RequestParametersFrom.Uri<*>)?.url,
        parent = when (value) {
            is RequestParametersFrom.JwsSigned -> value.parent
            is RequestParametersFrom.Json -> value.parent
            else -> null
        },
        dcApiRequest = when (value) {
            is RequestParametersFrom.DcApiRequest -> joseCompliantSerializer.encodeToJsonElement(value.dcApiRequest) as? JsonObject
            else -> null
        },
        verified = (value as? RequestParametersFrom.JwsSigned<*>)?.verified,
    )

    fun toRequestParametersFrom(): RequestParametersFrom<T> = when {
        jwsCompact != null && dcApiRequest != null ->
            RequestParametersFrom.DcApiSigned(
                dcApiRequest = joseCompliantSerializer.decodeFromJsonElement(dcApiRequest),
                parameters = parameters,
                jwsSigned = jwsCompact,
            )

        jsonString != null && dcApiRequest != null ->
            RequestParametersFrom.DcApiUnsigned(
                dcApiRequest = joseCompliantSerializer.decodeFromJsonElement(dcApiRequest),
                parameters = parameters,
                jsonString = jsonString,
            )

        jsonString != null ->
            RequestParametersFrom.Json(
                jsonString = jsonString,
                parameters = parameters,
                parent = parent,
            )

        jwsCompact != null ->
            RequestParametersFrom.JwsSigned(
                jwsSigned = jwsCompact,
                parameters = parameters,
                verified = verified ?: false,
                parent = parent,
            )

        url != null ->
            RequestParametersFrom.Uri(
                url = url,
                parameters = parameters,
            )

        else -> throw SerializationException("Unknown RequestParametersFrom surrogate. Input: $this")
    }
}