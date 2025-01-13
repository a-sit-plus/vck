package at.asitplus.wallet.lib.oidc.helper

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.json
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.json.JsonObject

class RequestParser(
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a [JsonWebKeySet],
     * or the request itself as `request_uri`, or `presentation_definition_uri`.
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    /**
     * Need to verify the request object serialized as a JWS,
     * which may be signed with a pre-registered key (see [OpenIdConstants.ClientIdScheme.PreRegistered]).
     */
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { _: Any -> true },
) {
    /**
     * Pass in the URL sent by the Verifier (containing the [RequestParameters] as query parameters),
     * to create [AuthenticationResponseParameters] that can be sent back to the Verifier, see
     * [AuthenticationResponseResult].
     */
    suspend fun parseRequestParameters(input: String): KmmResult<RequestParametersFrom<*>> = catching {
        // maybe it is a request JWS
        val parsedParams = kotlin.run { parseRequestObjectJws(input) }
            ?: kotlin.runCatching { // maybe it's in the URL parameters
                Url(input).let {
                    val params = it.parameters.flattenEntries().toMap().decodeFromUrlQuery<JsonObject>()
                    val parsed = json.decodeFromJsonElement(PolymorphicSerializer(RequestParameters::class), params)
                    matchRequestParameterCases(it, parsed)
                }
            }.onFailure {
                Napier.d("parseRequestParameters: Failed for $input", it)
            }.getOrNull()
            ?: catching {  // maybe it is already a JSON string
                val params = vckJsonSerializer.decodeFromString(PolymorphicSerializer(RequestParameters::class), input)
                matchRequestParameterCases(input, params)
            }.getOrNull()
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("Could not parse authentication request: $input") }

        (parsedParams.parameters as? AuthenticationRequestParameters)?.let {
            extractRequestObject(it)
        } ?: parsedParams
            .also { Napier.i("Parsed authentication request: $it") }
    }

    private suspend fun extractRequestObject(params: AuthenticationRequestParameters): RequestParametersFrom<*>? =
        params.request?.let { requestObject ->
            parseRequestObjectJws(requestObject)
        } ?: params.requestUri?.let { uri ->
            remoteResourceRetriever.invoke(uri)
                ?.let { parseRequestParameters(it).getOrNull() }
        }

    private fun parseRequestObjectJws(requestObject: String): RequestParametersFrom<*>? =
        JwsSigned.deserialize<RequestParameters>(
            PolymorphicSerializer(RequestParameters::class),
            requestObject,
            vckJsonSerializer
        ).onFailure {
            Napier.d("parseRequestObjectJws: Error for $requestObject", it)
        }.getOrNull()?.let { jws ->
            if (requestObjectJwsVerifier.invoke(jws)) {
                RequestParametersFrom.JwsSigned(jws, jws.payload)
            } else {
                Napier.w("parseRequestObjectJws: Signature not verified for $jws")
                null
            }
        }

    @Suppress("UNCHECKED_CAST")
    private fun <T> matchRequestParameterCases(input: T, params: RequestParameters): RequestParametersFrom<*> =
        when (params) {
            is AuthenticationRequestParameters ->
                when (input) {
                    is Url -> RequestParametersFrom.Uri(input, params)
                    is JwsSigned<*> -> RequestParametersFrom.JwsSigned(input as JwsSigned<RequestParameters>, params)
                    is String -> RequestParametersFrom.Json(input, params)
                    else -> throw Exception("matchRequestParameterCases: unknown type ${input?.let { it::class.simpleName } ?: "null"}")
                }

            else -> throw NotImplementedError("matchRequestParameterCases: ${params::class.simpleName} not implemented")
        }
}