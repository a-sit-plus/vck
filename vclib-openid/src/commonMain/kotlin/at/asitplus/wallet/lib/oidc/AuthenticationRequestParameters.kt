package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.InstantLongSerializer
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.oidvci.AuthorizationDetails
import io.github.aakira.napier.Napier
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Contents of an OIDC Authentication Request.
 *
 * Usually, these parameters are appended to the Authorization Endpoint URL of the OpenId Provider (may be the
 * Wallet App in case of SIOPv2, or the Credential Issuer for OID4VCI).
 */
@Serializable
data class AuthenticationRequestParameters(
    /**
     * OIDC: REQUIRED. OAuth 2.0 Response Type value that determines the authorization processing flow to be used,
     * including what parameters are returned from the endpoints used. When using the Authorization Code Flow, this
     * value is `code`.
     *
     * For OIDC SIOPv2, this is typically `id_token`. For OID4VP, this is typically `vp_token`.
     *
     * Optional when JAR (RFC9101) is used.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.responseType)
    val responseType: String? = null,

    /**
     * OIDC: REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.clientId)
    val clientId: String,

    /**
     * OIDC: REQUIRED. Redirection URI to which the response will be sent. This URI MUST exactly match one of the
     * Redirection URI values for the Client pre-registered at the OpenID Provider, with the matching performed as
     * described in Section 6.2.1 of RFC3986 (Simple String Comparison).
     *
     * Optional when JAR (RFC9101) is used.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.redirectUrl)
    val redirectUrl: String? = null,

    /**
     * OIDC: REQUIRED. OpenID Connect requests MUST contain the openid scope value. If the openid scope value is not
     * present, the behavior is entirely unspecified. Other scope values MAY be present. Scope values used that are not
     * understood by an implementation SHOULD be ignored.
     * e.g. `profile` or `com.example.healthCardCredential`
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.scope)
    val scope: String? = null,

    /**
     * OIDC: RECOMMENDED. Opaque value used to maintain state between the request and the callback. Typically,
     * Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this
     * parameter with a browser cookie.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.state)
    val state: String? = null,

    /**
     * OIDC: OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
     * The value is passed through unmodified from the Authentication Request to the ID Token. Sufficient entropy MUST
     * be present in the nonce values used to prevent attackers from guessing values.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.nonce)
    val nonce: String? = null,

    /**
     * OIDC: OPTIONAL. This parameter is used to request that specific Claims be returned. The value is a JSON object
     * listing the requested Claims.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.claims)
    val claims: AuthnRequestClaims? = null,

    /**
     * OIDC SIOPv2: OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP
     * that would normally be provided to an OP during Dynamic RP Registration.
     * It MUST not be present if the RP uses OpenID Federation 1.0 Automatic Registration to pass its metadata.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.clientMetadata)
    val clientMetadata: RelyingPartyMetadata? = null,

    /**
     * OIDC SIOPv2: OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP
     * that would normally be provided to an OP during Dynamic RP Registration.
     * It MUST not be present if the RP uses OpenID Federation 1.0 Automatic Registration to pass its metadata.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.clientMetadataUri)
    val clientMetadataUri: String? = null,

    /**
     * OIDC: OPTIONAL. ID Token previously issued by the Authorization Server being passed as a hint about the
     * End-User's current or past authenticated session with the Client. If the End-User identified by the ID Token is
     * logged in or is logged in by the request, then the Authorization Server returns a positive response; otherwise,
     * it SHOULD return an error, such as login_required.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.idTokenHint)
    val idTokenHint: String? = null,

    /**
     * OAuth 2.0 JAR: REQUIRED unless `request_uri` is specified. The Request Object that holds authorization request
     * parameters stated in Section 4 of RFC6749 (OAuth 2.0). If this parameter is present in the authorization request,
     * `request_uri` MUST NOT be present.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.request)
    val request: String? = null,

    /**
     * OAuth 2.0 JAR: REQUIRED unless request is specified. The absolute URI, as defined by RFC3986, that is the
     * Request Object URI referencing the authorization request parameters stated in Section 4 of RFC6749 (OAuth 2.0).
     * If this parameter is present in the authorization request, `request` MUST NOT be present.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.requestUri)
    val requestUri: String? = null,

    /**
     * OIDC SIOPv2: OPTIONAL. Space-separated string that specifies the types of ID Token the RP wants to obtain, with
     * the values appearing in order of preference. The allowed individual values are `subject_signed_id_token` and
     * `attester_signed_id_token`. The default value is `attester_signed_id_token`. The RP determines the type if
     * ID Token returned based on the comparison of the `iss` and `sub` claims values. In order to preserve
     * compatibility with existing OpenID Connect deployments, the OP MAY return an ID Token that does not fulfill the
     * requirements as expressed in this parameter. So the RP SHOULD be prepared to reliably handle such an outcome.
     *
     * See [IdTokenType] for valid values.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.idTokenType)
    val idTokenType: String? = null,

    /**
     * OID4VP: A string containing a Presentation Definition JSON object. This parameter MUST be present when
     * `presentation_definition_uri` parameter, or a `scope` value representing a Presentation Definition is not
     * present.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.presentationDefinition)
    val presentationDefinition: PresentationDefinition? = null,

    /**
     * OID4VP: A string containing an HTTPS URL pointing to a resource where a Presentation Definition JSON object can
     * be retrieved. This parameter MUST be present when `presentation_definition` parameter, or a `scope` value
     * representing a Presentation Definition is not present.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.authorizationDetails)
    val authorizationDetails: AuthorizationDetails? = null,

    /**
     * OID4VP: OPTIONAL. A string identifying the scheme of the value in the `client_id` Authorization Request parameter
     * (Client Identifier scheme). The `client_id_scheme` parameter namespaces the respective Client Identifier. If an
     * Authorization Request uses the `client_id_scheme` parameter, the Wallet MUST interpret the Client Identifier of
     * the Verifier in the context of the Client Identifier scheme. If the parameter is not present, the Wallet MUST
     * behave as specified in RFC6749. If the same Client Identifier is used with different Client Identifier schemes,
     * those occurrences MUST be treated as different Verifiers. Note that the Verifier needs to determine which Client
     * Identifier schemes the Wallet supports prior to sending the Authorization Request in order to choose a supported
     * scheme.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.clientIdScheme)
    val clientIdScheme: String? = null,

    /**
     * OID4VP: OPTIONAL. String containing the Wallet's identifier. The Credential Issuer can use the discovery process
     * defined in SIOPv2 to determine the Wallet's capabilities and endpoints, using the `wallet_issuer` value as the
     * Issuer Identifier referred to in SIOPv2. This is RECOMMENDED in Dynamic Credential Requests.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.walletIssuer)
    val walletIssuer: String? = null,

    /**
     * OID4VP: OPTIONAL. String containing an opaque End-User hint that the Wallet MAY use in subsequent callbacks to
     * optimize the End-User's experience. This is RECOMMENDED in Dynamic Credential Requests.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.userHint)
    val userHint: String? = null,

    /**
     * OID4VP: OPTIONAL. String value identifying a certain processing context at the Credential Issuer. A value for
     * this parameter is typically passed in a Credential Offer from the Credential Issuer to the Wallet. This request
     * parameter is used to pass the issuer_state value back to the Credential Issuer.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.issuerState)
    val issuerState: String? = null,

    /**
     * OAuth 2.0 Responses: OPTIONAL. Informs the Authorization Server of the mechanism to be used for returning
     * Authorization Response parameters from the Authorization Endpoint. This use of this parameter is NOT RECOMMENDED
     * with a value that specifies the same Response Mode as the default Response Mode for the Response Type used.
     *
     * OIDC SIOPv2: This response mode `post` is used to request the Self-Issued OP to deliver the result of the
     * authentication process to a certain endpoint using the HTTP POST method.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.responseMode)
    val responseMode: String? = null,

    /**
     * OID4VP: OPTIONAL. The Response URI to which the Wallet MUST send the Authorization Response using an HTTPS POST
     * request as defined by the Response Mode `direct_post`. The Response URI receives all Authorization Response
     * parameters as defined by the respective Response Type. When the `response_uri` parameter is present,
     * the `redirect_uri` Authorization Request parameter MUST NOT be present. If the `redirect_uri` Authorization
     * Request parameter is present when the Response Mode is `direct_post`, the Wallet MUST return an
     * `invalid_request` Authorization Response error.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.responseUrl)
    val responseUrl: String? = null,

    /**
     * OAuth 2.0 JAR: If signed, the Authorization Request Object SHOULD contain the Claims `iss` (issuer) and `aud`
     * (audience) as members with their semantics being the same as defined in the JWT (RFC7519) specification. The
     * value of `aud` should be the value of the authorization server (AS) `issuer`, as defined in RFC 8414.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.audience)
    val audience: String? = null,

    /**
     * OAuth 2.0 JAR: If signed, the Authorization Request Object SHOULD contain the Claims `iss` (issuer) and `aud`
     * (audience) as members with their semantics being the same as defined in the JWT (RFC7519) specification. The
     * value of `aud` should be the value of the authorization server (AS) `issuer`, as defined in RFC 8414.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.issuer)
    val issuer: String? = null,

    /**
     * OPTIONAL. Time at which the request was issued.
     */
    @SerialName(AuthenticationRequestConstants.SerialNames.issuedAt)
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<AuthenticationRequestParameters>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}

// restricted to internal as there is no reason to make this public for now
object AuthenticationRequestConstants {
    object SerialNames {

        const val audience = "aud"
        const val authorizationDetails = "authorization_details"
        const val claims = "claims"
        const val clientId = "client_id"
        const val clientIdScheme = "client_id_scheme"
        const val clientMetadata = "client_metadata"
        const val clientMetadataUri = "client_metadata_uri"
        const val idTokenHint = "id_token_hint"
        const val idTokenType = "id_token_type"
        const val issuedAt = "iat"
        const val issuer = "iss"
        const val issuerState = "issuer_state"
        const val nonce = "nonce"
        const val presentationDefinition = "presentation_definition"
        const val presentationDefinitionUri = "presentation_definition_uri"
        const val redirectUrl = "redirect_uri"
        const val request = "request"
        const val requestUri = "request_uri"
        const val responseMode = "response_mode"
        const val responseType = "response_type"
        const val responseUrl = "response_uri"
        const val scope = "scope"
        const val state = "state"
        const val userHint = "user_hint"
        const val walletIssuer = "wallet_issuer"
    }
}