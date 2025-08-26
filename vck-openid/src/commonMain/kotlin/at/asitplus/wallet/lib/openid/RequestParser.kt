package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.dcapi.request.DCAPIRequest
import at.asitplus.openid.*
import at.asitplus.openid.JarRequestParameters.RequestUriMethod
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.json
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonObject

class RequestParser(
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a [at.asitplus.signum.indispensable.josef.JsonWebKeySet],
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
    /**
     * Callback to load [RequestObjectParameters] when loading a request object by reference (e.g. from `request_uri`)
     */
    private val buildRequestObjectParameters: suspend () -> RequestObjectParameters? = { null },
) {
    /**
     * Pass in the request by a relying party, that is either a complete URL,
     * or the POST body (e.g. the form-serialized values of the authorization request),
     * or a serialized JWS (which may have been extracted from a `request` parameter),
     * to parse the [AuthenticationRequestParameters], wrapped in [RequestParametersFrom].
     */
    suspend fun parseRequestParameters(
        input: String,
        dcApiRequest: DCAPIRequest? = null
    ): KmmResult<RequestParametersFrom<*>> = catching {
        // maybe it is a request JWS
        val parsedParams = run { parseRequestObjectJws(input, dcApiRequest) }
            ?: catchingUnwrapped { // maybe it's in the URL parameters
                Url(input).let {
                    val params = it.parameters.flattenEntries().toMap().decodeFromUrlQuery<JsonObject>()
                    val parsed = json.decodeFromJsonElement(RequestParameters.serializer(),params)
                    matchRequestParameterCases(it, parsed, dcApiRequest)
                }
            }.onFailure {
                Napier.v("parseRequestParameters: Failed for $input", it)
            }.getOrNull()
            ?: catching {  // maybe it is already a JSON string
                val params = vckJsonSerializer.decodeFromString(RequestParameters.serializer(), input)
                matchRequestParameterCases(input, params, dcApiRequest)
            }.onFailure {
                Napier.v("parseRequestParameters: Failed for $input", it)
            }.getOrNull()
            ?: throw InvalidRequest("parse error")
                .also { Napier.w("Could not parse authentication request: $input") }

        (parsedParams.parameters as? JarRequestParameters)?.let {
            extractRequestParameterFromJAR(it, dcApiRequest)
        } ?: parsedParams
            .also { Napier.i("Parsed authentication request: $it") }
    }

    suspend fun extractRequestParameterFromJAR(
        params: JarRequestParameters,
        dcApiRequest: DCAPIRequest? = null
    ): RequestParametersFrom<*>? =
        params.request?.let { requestObject ->
            parseRequestObjectJws(requestObject, dcApiRequest)
        } ?: params.requestUri?.let { uri ->
            remoteResourceRetriever.invoke(params.resourceRetrieverInput(uri))
                ?.let { parseRequestParameters(it).getOrNull() }
        }

    private suspend fun JarRequestParameters.resourceRetrieverInput(
        uri: String,
    ): RemoteResourceRetrieverInput = RemoteResourceRetrieverInput(
        url = uri,
        method = if (requestUriMethod == RequestUriMethod.POST) HttpMethod.Post else HttpMethod.Get,
        headers = mapOf(HttpHeaders.Accept to MediaTypes.AUTHZ_REQ_JWT),
        requestObjectParameters = buildRequestObjectParameters.invoke()
    )

    private suspend fun parseRequestObjectJws(
        requestObject: String,
        dcApiRequest: DCAPIRequest? = null
    ): RequestParametersFrom<*>? =
        JwsSigned.deserialize<RequestParameters>(
            RequestParameters.serializer(),
            requestObject,
            vckJsonSerializer
        ).onFailure {
            Napier.v("parseRequestObjectJws: Error for $requestObject", it)
        }.getOrNull()?.let { jws ->
            if (requestObjectJwsVerifier.invoke(jws)) {
                RequestParametersFrom.JwsSigned(jws, jws.payload, dcApiRequest)
            } else {
                Napier.w("parseRequestObjectJws: Signature not verified for $jws")
                null
            }
        }

    @Suppress("UNCHECKED_CAST")
    private fun <T> matchRequestParameterCases(
        input: T,
        params: RequestParameters,
        dcApiRequest: DCAPIRequest? = null
    ): RequestParametersFrom<*> =
        when (input) {
            is Url -> RequestParametersFrom.Uri(input, params)
            is JwsSigned<*> -> RequestParametersFrom.JwsSigned(
                input as JwsSigned<RequestParameters>,
                params,
                dcApiRequest
            )
            is String -> RequestParametersFrom.Json(input, params, dcApiRequest)
            else -> throw Exception("matchRequestParameterCases: unknown type ${input?.let { it::class.simpleName } ?: "null"}")
        }
}
