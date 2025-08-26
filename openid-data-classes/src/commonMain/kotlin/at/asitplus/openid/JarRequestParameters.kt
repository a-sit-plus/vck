package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class JarRequestParameters(
    /**
     * OIDC: REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server.
     *
     * DC API: The client_id parameter MUST be omitted in unsigned requests defined in Appendix
     * A.3.1. The Wallet MUST ignore any client_id parameter that is present in an unsigned request.
     * The client_id parameter MUST be present in signed requests defined in Appendix A.3.2,
     * as it communicates to the wallet which Client Identifier Prefix and Client Identifier to use
     * when authenticating the client through verification of the request signature or retrieving
     * client metadata.
     *
     * See also [clientIdWithoutPrefix] and the notes there.
     */
    @SerialName("client_id")
    val clientId: String? = null,

    /**
     * OAuth 2.0 JAR: REQUIRED unless `request_uri` is specified. The Request Object that holds authorization request
     * parameters stated in Section 4 of RFC6749 (OAuth 2.0). If this parameter is present in the authorization request,
     * `request_uri` MUST NOT be present.
     */
    @SerialName("request")
    val request: String? = null,

    /**
     * OAuth 2.0 JAR: REQUIRED unless request is specified. The absolute URI, as defined by RFC3986, that is the
     * Request Object URI referencing the authorization request parameters stated in Section 4 of RFC6749 (OAuth 2.0).
     * If this parameter is present in the authorization request, `request` MUST NOT be present.
     */
    @SerialName("request_uri")
    val requestUri: String? = null,

    /**
     * OpenID4VP: OPTIONAL. A string determining the HTTP method to be used when the [requestUri] parameter is included
     * in the same request. Two case-sensitive valid values are defined in this specification: `get` and `post`.
     * If [requestUriMethod] value is `get`, the Wallet MUST send the request to retrieve the Request Object using the
     * HTTP GET method, i.e., as defined in RFC9101. If [requestUriMethod] value is `post`, a supporting Wallet MUST
     * send the request using the HTTP POST method as detailed in Section 5.11. If the [requestUriMethod] parameter is
     * not present, the Wallet MUST process the [requestUri] parameter as defined in RFC9101. Wallets not supporting
     * the post method will send a GET request to the Request URI (default behavior as defined in RFC9101).
     * [requestUriMethod] parameter MUST NOT be present if a [requestUri] parameter is not present.
     */
    @SerialName("request_uri_method")
    val requestUriMethod: RequestUriMethod? = null,

    @SerialName("state")
    val state: String? = null,
) : RequestParameters() {

    @Serializable
    enum class RequestUriMethod{
        @SerialName("get")
        GET,
        @SerialName("post")
        POST,
    }
}
