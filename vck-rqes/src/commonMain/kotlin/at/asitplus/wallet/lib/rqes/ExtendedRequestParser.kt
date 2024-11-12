package at.asitplus.wallet.lib.rqes
//
//import at.asitplus.openid.OpenIdConstants
//import at.asitplus.signum.indispensable.josef.JsonWebKeySet
//import at.asitplus.wallet.lib.oidc.RemoteResourceRetrieverFunction
//import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
//import at.asitplus.wallet.lib.oidc.helper.RequestParser
//import io.ktor.http.*
//
///**
// * This class replaces [RequestParser] in [OidcSiopWallet] when
// * we know that we need to handle Rqes Requests
// */
//class ExtendedRequestParser(
//    /**
//     * Need to implement if resources are defined by reference, i.e. the URL for a [JsonWebKeySet],
//     * or the request itself as `request_uri`, or `presentation_definition_uri`.
//     * Implementations need to fetch the url passed in, and return either the body, if there is one,
//     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
//     */
//    remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
//    /**
//     * Need to verify the request object serialized as a JWS,
//     * which may be signed with a pre-registered key (see [OpenIdConstants.ClientIdScheme.PreRegistered]).
//     */
//    requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { _ -> true },
//) : RequestParser(remoteResourceRetriever, requestObjectJwsVerifier) {
////    override fun <T> matchRequestParameterCases(input: T, params: RequestParameters): RequestParametersFrom =
////        when (params) {
////            is AuthenticationRequestParameters ->
////                when (input) {
////                    is Url -> AuthenticationRequestParametersFrom.Uri(input, params)
////                    is JwsSigned<*> -> AuthenticationRequestParametersFrom.JwsSigned(input as JwsSigned<ByteArray>, params)
////                    is String -> AuthenticationRequestParametersFrom.Json(input, params)
////                    else -> throw Exception("matchRequestParameterCases: unknown type ${input?.let { it::class.simpleName } ?: "null"}")
////                }
////
////            is SignatureRequestParameters ->
////                when (input) {
////                    is Url -> SignatureRequestParametersFrom.Uri(input, params)
////                    is JwsSigned<*> -> SignatureRequestParametersFrom.JwsSigned(input as JwsSigned<ByteArray>, params)
////                    is String -> SignatureRequestParametersFrom.Json(input, params)
////                    else -> throw Exception("matchRequestParameterCases: unknown type ${input?.let { it::class.simpleName } ?: "null"}")
////                }
////
////            else -> throw NotImplementedError("matchRequestParameterCases: ${params::class.simpleName} not implemented")
////        }
//}