package at.asitplus.wallet.lib.oidc.helper

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.RequestParametersSerializer
import at.asitplus.openid.SignatureRequestParameters
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParametersFrom
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidc.RequestParametersFrom
import at.asitplus.wallet.lib.oidc.SignatureRequestParametersFrom
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier
import io.ktor.http.*
import kotlinx.serialization.json.encodeToJsonElement

class RequestParser(
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a [JsonWebKeySet],
     * or the authentication request itself as `request_uri`, or `presentation_definition_uri`.
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction,
    /**
     * Need to verify the request object serialized as a JWS,
     * which may be signed with a pre-registered key (see [OpenIdConstants.ClientIdScheme.PreRegistered]).
     */
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier,
) {
    companion object {
        fun createWithDefaults(
            remoteResourceRetriever: RemoteResourceRetrieverFunction? = null,
            requestObjectJwsVerifier: RequestObjectJwsVerifier? = null,
        ) = RequestParser(
            remoteResourceRetriever = remoteResourceRetriever ?: { null },
            requestObjectJwsVerifier = requestObjectJwsVerifier ?: RequestObjectJwsVerifier { _, _ -> true },
        )
    }

    /**
     * Pass in the URL sent by the Verifier (containing the [AuthenticationRequestParameters] as query parameters),
     * to create [AuthenticationResponseParameters] that can be sent back to the Verifier, see
     * [AuthenticationResponseResult].
     * TODO finish all cases as in URI
     */
    suspend fun parseRequestParameters(input: String): KmmResult<RequestParametersFrom> = catching {
        // maybe it is a request JWS
        val parsedParams = kotlin.run { parseRequestObjectJws(input) }
            ?: kotlin.runCatching { // maybe it's in the URL parameters
                Url(input).let {
                    val params =
                        vckJsonSerializer.encodeToJsonElement(it.parameters) //ToDo Double check if this in-between step is necessary
                    vckJsonSerializer.decodeFromJsonElement(RequestParametersSerializer, params).let { result ->
                        when (result) {
                            is AuthenticationRequestParameters ->
                                AuthenticationRequestParametersFrom.Uri(it, result)

                            is SignatureRequestParameters ->
                                SignatureRequestParametersFrom.Uri(it, result)
                                    .also { Napier.d { "It did make a difference for URI" } }
                        }
                    }
                }
            }.onFailure { it.printStackTrace() }.getOrNull()
            ?: catching {  // maybe it is already a JSON string
//                val params = AuthenticationRequestParameters.deserialize(input).getOrThrow()
//                AuthenticationRequestParametersFrom.Json(input, params)
                val params = vckJsonSerializer.decodeFromString(RequestParametersSerializer, input)
                when (params) {
                    is AuthenticationRequestParameters ->
                        AuthenticationRequestParametersFrom.Json(input, params)

                    is SignatureRequestParameters ->
                        SignatureRequestParametersFrom.Json(input, params)
                            .also { Napier.d { "It did make a difference for Json" } }
                }
            }.getOrNull()
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("Could not parse authentication request: $input") }

        Napier.d { "it is of type ${parsedParams::class}" }
        val extractedParams =
            parsedParams.let { extractRequestObject(it.parameters as AuthenticationRequestParameters) ?: it }
                .also { Napier.i("Parsed authentication request: $it") }
        extractedParams
    }

    private suspend fun extractRequestObject(params: AuthenticationRequestParameters): RequestParametersFrom? =
        params.request?.let { requestObject ->
            parseRequestObjectJws(requestObject)
        } ?: params.requestUri?.let { uri ->
            remoteResourceRetriever.invoke(uri)
                ?.let { parseRequestParameters(it).getOrNull() }
        }

    private fun parseRequestObjectJws(requestObject: String): RequestParametersFrom? {
        return JwsSigned.deserialize(requestObject).getOrNull()?.let { jws ->
            val params = kotlin.runCatching {
                vckJsonSerializer.decodeFromString(
                    RequestParametersSerializer,
                    jws.payload.decodeToString()
                )
            }.getOrElse {
                return null
                    .apply { Napier.w("parseRequestObjectJws: Deserialization failed", it) }
            }
            if (requestObjectJwsVerifier.invoke(jws, params)) {
                when (params) {
                    is AuthenticationRequestParameters ->
                        AuthenticationRequestParametersFrom.JwsSigned(jws, params)

                    is SignatureRequestParameters ->
                        SignatureRequestParametersFrom.JwsSigned(jws, params)
                            .also { Napier.d { "It did make a difference for JwsSigned" } }
                }
            } else null
                .also { Napier.w("parseRequestObjectJws: Signature not verified for $jws") }
        }
    }

}