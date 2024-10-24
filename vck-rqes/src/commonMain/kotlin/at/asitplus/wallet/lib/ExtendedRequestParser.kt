package at.asitplus.wallet.lib

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationRequestParametersFrom
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.rqes.SignatureRequestParameters
import at.asitplus.rqes.SignatureRequestParametersFrom
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.oidc.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidc.helper.RequestParser
import io.ktor.http.*

/**
 * This class replaces [RequestParser] in [OidcSiopWallet] when
 * we know that we need to handle Rqes Requests
 */
class ExtendedRequestParser(
    remoteResourceRetriever: RemoteResourceRetrieverFunction,
    requestObjectJwsVerifier: RequestObjectJwsVerifier,
) : RequestParser(remoteResourceRetriever, requestObjectJwsVerifier) {
    override fun <T> matchRequestParameterCases(input: T, params: RequestParameters): RequestParametersFrom {
        return when (params) {
            is AuthenticationRequestParameters ->
                when (input) {
                    is Url -> AuthenticationRequestParametersFrom.Uri(input, params)
                    is JwsSigned -> AuthenticationRequestParametersFrom.JwsSigned(input, params)
                    is String -> AuthenticationRequestParametersFrom.Json(input, params)
                    else -> throw Exception("matchRequestParameterCases: unknown type ${input?.let { it::class.simpleName } ?: "null"}")
                }
            is SignatureRequestParameters ->
                when (input) {
                    is Url -> SignatureRequestParametersFrom.Uri(input, params)
                    is JwsSigned -> SignatureRequestParametersFrom.JwsSigned(input, params)
                    is String -> SignatureRequestParametersFrom.Json(input, params)
                    else -> throw Exception("matchRequestParameterCases: unknown type ${input?.let { it::class.simpleName } ?: "null"}")
                }

            else -> TODO()
        }
    }

    companion object {
        fun createWithDefaults(
            remoteResourceRetriever: RemoteResourceRetrieverFunction? = null,
            requestObjectJwsVerifier: RequestObjectJwsVerifier? = null,
        ) = RequestParser(
            remoteResourceRetriever = remoteResourceRetriever ?: { null },
            requestObjectJwsVerifier = requestObjectJwsVerifier ?: RequestObjectJwsVerifier { _, _ -> true },
        )
    }
}