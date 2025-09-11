package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.dcapi.request.DCAPIRequest
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.json
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonObject

class RequestParser(
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a
     * [at.asitplus.signum.indispensable.josef.JsonWebKeySet],
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
        dcApiRequest: DCAPIRequest? = null,
    ): KmmResult<RequestParametersFrom<*>> = catching {
        input.parseParameters(dcApiRequest).extractRequestObject(dcApiRequest)
    }

    private suspend fun String.parseParameters(
        dcApiRequest: DCAPIRequest?,
    ): RequestParametersFrom<out RequestParameters> =
        parseAsRequestObjectJws(dcApiRequest)
            ?: parseFromParameters()
            ?: parseFromJson(dcApiRequest)
            ?: throw InvalidRequest("parse error: $this")

    private suspend fun RequestParametersFrom<out RequestParameters>.extractRequestObject(
        dcApiRequest: DCAPIRequest?,
    ): RequestParametersFrom<*> =
        (this.parameters as? AuthenticationRequestParameters)?.extractRequestObject(dcApiRequest) ?: this

    private fun String.parseFromParameters(): RequestParametersFrom<*>? = catchingUnwrapped {
        Url(this).let {
            RequestParametersFrom.Uri(
                url = it,
                parameters = json.decodeFromJsonElement(
                    RequestParameters.serializer(),
                    it.parameters.flattenEntries().toMap().decodeFromUrlQuery<JsonObject>()
                )
            )
        }
    }.getOrNull()

    private fun String.parseFromJson(
        dcApiRequest: DCAPIRequest?,
    ): RequestParametersFrom<*>? = catching {
        val params = vckJsonSerializer.decodeFromString(RequestParameters.serializer(), this)
        RequestParametersFrom.Json(this, params, dcApiRequest)
    }.getOrNull()

    /**
     * Extracts the actual request, referenced by the passed-in [input],
     * e.g. extracting [AuthenticationRequestParameters.request]
     * or [AuthenticationRequestParameters.requestUri] if necessary.
     */
    suspend fun extractActualRequest(
        input: AuthenticationRequestParameters,
    ): KmmResult<AuthenticationRequestParameters> = catching {
        input.extractRequest()
    }

    private suspend fun AuthenticationRequestParameters.extractRequest(
    ): AuthenticationRequestParameters =
        request?.let { it.parseAsRequestObjectJws()?.parameters as? AuthenticationRequestParameters }
            ?: requestUri
                ?.let { uri -> remoteResourceRetriever.invoke(resourceRetrieverInput(uri)) }
                ?.let { parseRequestParameters(it).getOrNull()?.parameters as? AuthenticationRequestParameters }
            ?: this

    private suspend fun AuthenticationRequestParameters.extractRequestObject(
        dcApiRequest: DCAPIRequest?,
    ): RequestParametersFrom<*>? = request?.let {
        it.parseAsRequestObjectJws(dcApiRequest)
            ?: it.parseFromJson(dcApiRequest)
    } ?: requestUri
        ?.let { remoteResourceRetriever.invoke(resourceRetrieverInput(it)) }
        ?.let {
            it.parseAsRequestObjectJws(dcApiRequest)
                ?: it.parseFromJson(dcApiRequest)
                ?: throw InvalidRequest("URL not valid: $requestUri")
        }


    private suspend fun AuthenticationRequestParameters.resourceRetrieverInput(
        uri: String,
    ): RemoteResourceRetrieverInput = RemoteResourceRetrieverInput(
        url = uri,
        method = requestUriMethod.toHttpMethod(),
        headers = mapOf(HttpHeaders.Accept to MediaTypes.Application.AUTHZ_REQ_JWT),
        requestObjectParameters = buildRequestObjectParameters.invoke()
    )

    private suspend fun String.parseAsRequestObjectJws(
        dcApiRequest: DCAPIRequest? = null,
    ): RequestParametersFrom<*>? =
        JwsSigned.deserialize(RequestParameters.serializer(), this, vckJsonSerializer)
            .getOrNull()?.let { jws ->
                if (requestObjectJwsVerifier.invoke(jws)) {
                    RequestParametersFrom.JwsSigned(jws, jws.payload, dcApiRequest)
                } else {
                    null
                }
            }

}

private fun String?.toHttpMethod(): HttpMethod = when (this) {
    "post" -> HttpMethod.Post
    else -> HttpMethod.Get
}
