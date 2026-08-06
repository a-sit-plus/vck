package at.asitplus.openid

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import at.asitplus.openid.RequestParametersFrom.SerialNames.JSON_STRING
import at.asitplus.openid.RequestParametersFrom.SerialNames.JWS
import at.asitplus.openid.RequestParametersFrom.SerialNames.PARAMETERS
import at.asitplus.openid.RequestParametersFrom.SerialNames.PARENT
import at.asitplus.openid.RequestParametersFrom.SerialNames.URL
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.JWS
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsFlattened
import at.asitplus.signum.indispensable.josef.JwsGeneral
import at.asitplus.signum.indispensable.josef.JwsTyped
import io.ktor.http.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException

/**
 * In order to de-/serialize generic types we need a kind of factory approach.
 * Because we deal with a sealed class we use an intermediary surrogate,
 * keeping the generic parameters and the fields identifying the concrete
 * [RequestParametersFrom] subtype.
 *
 * During serialization, the subtype is flattened into that surrogate. During
 * deserialization, the field combination determines the subtype again. DC API
 * request metadata is represented directly on the surrogate, matching
 * [RequestParametersFrom.DcApiRequest]. Plain JSON, JWS, and URI requests are
 * selected from their respective fields.
 * [JwsFlattened] is recognized but not implemented.
 */
class RequestParametersFromSerializer<T : RequestParameters>(
    parameterSerializer: KSerializer<T>,
) : KSerializer<RequestParametersFrom<T>> by TransformingSerializerTemplate(
    parent = RequestParametersFromSurrogate.serializer(parameterSerializer),
    encodeAs = { RequestParametersFromSurrogate(it) },
    decodeAs = { it.toRequestParametersFrom() }
)

@Serializable
private data class RequestParametersFromSurrogate<T : RequestParameters>(
    @SerialName(PARAMETERS)
    val parameters: T,
    @SerialName(JWS)
    val jws: JWS? = null,
    @SerialName(JSON_STRING)
    val jsonString: String? = null,
    @Serializable(UrlSerializer::class)
    @SerialName(URL)
    val url: Url? = null,
    @Serializable(UrlSerializer::class)
    @SerialName(PARENT)
    val parent: Url? = null,
    @SerialName(PROTOCOL)
    val protocol: ExchangeProtocolIdentifier? = null,
    @SerialName(CREDENTIAL_IDS)
    val credentialIds: Collection<String>? = null,
    @SerialName(CALLING_PACKAGE_NAME)
    val callingPackageName: String? = null,
    @SerialName(CALLING_ORIGIN)
    val callingOrigin: String? = null,
) {
    constructor(value: RequestParametersFrom<T>) : this(
        parameters = value.parameters,
        jws = when (value) {
            is RequestParametersFrom.Jws -> value.jws
            is RequestParametersFrom.RequestParametersSigned -> value.jwsTyped.jws
            else -> null
        },
        jsonString = when (value) {
            is RequestParametersFrom.OpenId4VpDcApiUnsigned -> value.jsonString
            is RequestParametersFrom.IsoMdocDcApi -> value.jsonString
            is RequestParametersFrom.Json -> value.jsonString
            else -> null
        },
        url = (value as? RequestParametersFrom.Uri<*>)?.url,
        parent = when (value) {
            is RequestParametersFrom.Jws -> value.parent
            is RequestParametersFrom.Json -> value.parent
            else -> null
        },
        protocol = when (value) {
            is RequestParametersFrom.OpenId4VpDcApiMultiSigned -> ExchangeProtocolIdentifier.OpenId4VpV1Multisigned
            is RequestParametersFrom.OpenId4VpDcApiSigned -> ExchangeProtocolIdentifier.OpenId4VpV1Signed
            is RequestParametersFrom.OpenId4VpDcApiUnsigned -> ExchangeProtocolIdentifier.OpenId4VpV1Unsigned
            is RequestParametersFrom.IsoMdocDcApi -> ExchangeProtocolIdentifier.IsoMdocAnnexC
            else -> null
        },
        credentialIds = (value as? RequestParametersFrom.DcApiRequest)?.credentialIds,
        callingPackageName = (value as? RequestParametersFrom.DcApiRequest)?.callingPackageName,
        callingOrigin = (value as? RequestParametersFrom.DcApiRequest)?.callingOrigin,
    )

    fun toRequestParametersFrom(): RequestParametersFrom<T> = when {
        protocol == ExchangeProtocolIdentifier.OpenId4VpV1Multisigned ->
            RequestParametersFrom.OpenId4VpDcApiMultiSigned(
                jwsTyped = JwsTyped(requireJwsGeneral(), requireAuthenticationRequestParameters()),
                credentialIds = requireCredentialIds(),
                callingPackageName = requireCallingPackageName(),
                callingOrigin = requireCallingOrigin(),
            ).cast()

        protocol == ExchangeProtocolIdentifier.OpenId4VpV1Signed ->
            RequestParametersFrom.OpenId4VpDcApiSigned(
                jwsTyped = JwsTyped(requireJwsCompact(), requireAuthenticationRequestParameters()),
                credentialIds = requireCredentialIds(),
                callingPackageName = requireCallingPackageName(),
                callingOrigin = requireCallingOrigin(),
            ).cast()

        protocol == ExchangeProtocolIdentifier.OpenId4VpV1Unsigned ->
            RequestParametersFrom.OpenId4VpDcApiUnsigned(
                parameters = requireAuthenticationRequestParameters(),
                jsonString = requireJsonString(),
                credentialIds = requireCredentialIds(),
                callingPackageName = requireCallingPackageName(),
                callingOrigin = requireCallingOrigin(),
            ).cast()

        protocol == ExchangeProtocolIdentifier.IsoMdocAnnexC ->
            RequestParametersFrom.IsoMdocDcApi(
                parameters = requireIsoMdocRequestWrapper(),
                jsonString = requireJsonString(),
                credentialIds = credentialIds,
                callingPackageName = callingPackageName,
                callingOrigin = requireCallingOrigin(),
            ).cast()

        jws is JwsFlattened -> throw UnsupportedOperationException("Not implemented yet")

        jsonString != null ->
            RequestParametersFrom.Json(
                jsonString = jsonString,
                parameters = parameters,
                parent = parent,
            )

        jws != null ->
            RequestParametersFrom.Jws(
                jws = jws,
                parameters = parameters,
                parent = parent,
            )

        url != null ->
            RequestParametersFrom.Uri(
                url = url,
                parameters = parameters,
            )

        else -> throw SerializationException("Unknown RequestParametersFrom surrogate. Input: $this")
    }

    private fun requireAuthenticationRequestParameters(): AuthenticationRequestParameters =
        parameters as? AuthenticationRequestParameters
            ?: throw SerializationException("Expected AuthenticationRequestParameters for protocol $protocol")

    private fun requireIsoMdocRequestWrapper(): RequestParametersFrom.IsoMdocDcApi.IsoMdocRequestWrapper =
        parameters as? RequestParametersFrom.IsoMdocDcApi.IsoMdocRequestWrapper
            ?: throw SerializationException("Expected IsoMdocRequestWrapper for protocol $protocol")

    private fun requireJwsCompact(): JwsCompact =
        jws as? JwsCompact
            ?: throw SerializationException("Expected compact JWS for protocol $protocol")

    private fun requireJwsGeneral(): JwsGeneral =
        jws as? JwsGeneral
            ?: throw SerializationException("Expected general JWS for protocol $protocol")

    private fun requireJsonString(): String =
        jsonString ?: throw SerializationException("Missing $JSON_STRING for protocol $protocol")

    private fun requireCredentialIds(): Collection<String> =
        credentialIds ?: throw SerializationException("Missing $CREDENTIAL_IDS for protocol $protocol")

    private fun requireCallingPackageName(): String =
        callingPackageName ?: throw SerializationException("Missing $CALLING_PACKAGE_NAME for protocol $protocol")

    private fun requireCallingOrigin(): String =
        callingOrigin ?: throw SerializationException("Missing $CALLING_ORIGIN for protocol $protocol")

    @Suppress("UNCHECKED_CAST")
    private fun RequestParametersFrom<*>.cast(): RequestParametersFrom<T> = this as RequestParametersFrom<T>
}

private const val PROTOCOL = "protocol"
private const val CREDENTIAL_IDS = "credentialIds"
private const val CALLING_PACKAGE_NAME = "callingPackageName"
private const val CALLING_ORIGIN = "callingOrigin"
