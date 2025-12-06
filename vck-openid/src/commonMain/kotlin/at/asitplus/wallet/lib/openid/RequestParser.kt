package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.dcapi.request.DCAPIWalletRequest
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
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
    ): KmmResult<RequestParametersFrom<*>> = catching {
        input.parseParameters().extractRequest()
    }

    /**
     * Pass in the data received by the DC API in signed or unsigned form. Will return [RequestParametersFrom].
     */
    suspend fun parseRequestParameters(
        input: DCAPIWalletRequest.OpenId4Vp,
    ): KmmResult<RequestParametersFrom<*>> = catching {
        input.parseAsDcApiRequest()?.extractRequest() ?: throw InvalidRequest("parse error: $input")
    }

    private suspend fun String.parseParameters(): RequestParametersFrom<out RequestParameters> =
            parseAsJwsRequest(null)
            ?: parseFromParameters()
            ?: parseFromJson(null)
            ?: throw InvalidRequest("parse error: $this")

    private suspend fun RequestParametersFrom<out RequestParameters>.extractRequest(): RequestParametersFrom<*> =
        (this.parameters as? JarRequestParameters)?.let { extractRequest(it, this) } ?: this

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
        parent: RequestParametersFrom<out RequestParameters>?,
    ): RequestParametersFrom<*>? = catchingUnwrapped {
        val params = vckJsonSerializer.decodeFromString(RequestParameters.serializer(), this)
        RequestParametersFrom.Json(this, params, (parent as? RequestParametersFrom.Uri)?.url)
    }.getOrNull()

    private fun DCAPIWalletRequest.OpenId4Vp.parseAsDcApiRequest(): RequestParametersFrom<*>? = catchingUnwrapped {
        when (this) {
            is DCAPIWalletRequest.OpenId4VpSigned -> {
                val requestStr = (this.request as? JarRequestParameters)?.request
                    ?: throw InvalidRequest("Did not find jar request parameters: $this")
                val jwsSigned = JwsSigned.deserialize(RequestParameters.serializer(), requestStr, vckJsonSerializer).getOrThrow()
                RequestParametersFrom.DcApiSigned(this, jwsSigned.payload, jwsSigned)
            }
            is DCAPIWalletRequest.OpenId4VpUnsigned -> {
                val jsonString = vckJsonSerializer.encodeToString(this.request)
                RequestParametersFrom.DcApiUnsigned(this, this.request, jsonString)
            }
        }
    }.getOrNull()

    suspend fun extractRequest(
        parameters: JarRequestParameters,
        parent: RequestParametersFrom<out RequestParameters>?,
    ): RequestParametersFrom<*>? = parameters.request?.let {
        it.parseAsJwsRequest(parent)
            ?: it.parseFromJson(parent)
    } ?: parameters.requestUri
        ?.let { remoteResourceRetriever.invoke(parameters.resourceRetrieverInput(it)) }
        ?.let {
            it.parseAsJwsRequest(parent)
                ?: it.parseFromJson(parent)
                ?: throw InvalidRequest("URL not valid: ${parameters.requestUri}")
        }

    private suspend fun JarRequestParameters.resourceRetrieverInput(
        uri: String,
    ): RemoteResourceRetrieverInput = RemoteResourceRetrieverInput(
        url = uri,
        method = requestUriMethod?.toHttpMethod() ?: HttpMethod.Get,
        headers = mapOf(HttpHeaders.Accept to MediaTypes.Application.AUTHZ_REQ_JWT),
        requestObjectParameters = buildRequestObjectParameters.invoke()
    )

    private suspend fun String.parseAsJwsRequest(
        parent: RequestParametersFrom<out RequestParameters>?,
    ): RequestParametersFrom<*>? =
        JwsSigned.deserialize(RequestParameters.serializer(), this, vckJsonSerializer)
            .getOrNull()?.let { jws ->
                RequestParametersFrom.JwsSigned(
                    jwsSigned = jws,
                    parameters = jws.payload,
                    verified = requestObjectJwsVerifier.invoke(jws),
                    parent = (parent as? RequestParametersFrom.Uri)?.url
                )
            }

}

