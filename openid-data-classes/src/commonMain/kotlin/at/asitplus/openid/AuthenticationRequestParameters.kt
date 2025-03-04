package at.asitplus.openid

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Contents of an OIDC Authentication Request.
 *
 * Usually, these parameters are appended to the Authorization Endpoint URL of the OpenId Provider (maybe the
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
    @SerialName("response_type")
    override val responseType: String? = null,

    /**
     * OIDC: REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server.
     *
     * See also [clientIdWithoutPrefix] and the notes there.
     */
    @SerialName("client_id")
    override val clientId: String? = null,

    /**
     * OIDC: REQUIRED. Redirection URI to which the response will be sent. This URI MUST exactly match one of the
     * Redirection URI values for the Client pre-registered at the OpenID Provider, with the matching performed as
     * described in Section 6.2.1 of RFC3986 (Simple String Comparison).
     *
     * Optional when JAR (RFC9101) is used.
     *
     * See also [redirectUrlExtracted]
     */
    @SerialName("redirect_uri")
    override val redirectUrl: String? = null,

    /**
     * OIDC: REQUIRED. OpenID Connect requests MUST contain the openid scope value. If the openid scope value is not
     * present, the behavior is entirely unspecified. Other scope values MAY be present. Scope values used that are not
     * understood by an implementation SHOULD be ignored.
     * e.g. `profile` or `com.example.healthCardCredential`
     */
    @SerialName("scope")
    val scope: String? = null,

    /**
     * OIDC: RECOMMENDED. Opaque value used to maintain state between the request and the callback. Typically,
     * Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this
     * parameter with a browser cookie.
     */
    @SerialName("state")
    override val state: String? = null,

    /**
     * OIDC: OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
     * The value is passed through unmodified from the Authentication Request to the ID Token. Sufficient entropy MUST
     * be present in the nonce values used to prevent attackers from guessing values.
     */
    @SerialName("nonce")
    override val nonce: String? = null,

    /**
     * OpenID4VP: When received in [RequestObjectParameters.walletNonce], the Verifier MUST use it as the [walletNonce]
     * value in the signed authorization request object.
     * Value can be a base64url-encoded, fresh, cryptographically random number with sufficient entropy.
     */
    @SerialName("wallet_nonce")
    val walletNonce: String? = null,

    /**
     * OIDC: OPTIONAL. This parameter is used to request that specific Claims be returned. The value is a JSON object
     * listing the requested Claims.
     */
    @SerialName("claims")
    val claims: AuthnRequestClaims? = null,

    /**
     * OIDC SIOPv2: OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP
     * that would normally be provided to an OP during Dynamic RP Registration.
     * It MUST not be present if the RP uses OpenID Federation 1.0 Automatic Registration to pass its metadata.
     */
    @SerialName("client_metadata")
    val clientMetadata: RelyingPartyMetadata? = null,

    /**
     * OIDC SIOPv2: OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP
     * that would normally be provided to an OP during Dynamic RP Registration.
     * It MUST not be present if the RP uses OpenID Federation 1.0 Automatic Registration to pass its metadata.
     */
    @SerialName("client_metadata_uri")
    val clientMetadataUri: String? = null,

    /**
     * OIDC: OPTIONAL. ID Token previously issued by the Authorization Server being passed as a hint about the
     * End-User's current or past authenticated session with the Client. If the End-User identified by the ID Token is
     * logged in or is logged in by the request, then the Authorization Server returns a positive response; otherwise,
     * it SHOULD return an error, such as login_required.
     */
    @SerialName("id_token_hint")
    val idTokenHint: String? = null,

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
    val requestUriMethod: String? = null,

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
    @SerialName("id_token_type")
    val idTokenType: String? = null,

    /**
     * OID4VP: A string containing a Presentation Definition JSON object. This parameter MUST be present when
     * [presentationDefinitionUrl] parameter, or a [scope] value representing a Presentation Definition is not
     * present.
     */
    @SerialName("presentation_definition")
    val presentationDefinition: PresentationDefinition? = null,

    /**
     * OID4VP: A string containing an HTTPS URL pointing to a resource where a Presentation Definition JSON object
     * can be retrieved. This parameter MUST be present when [presentationDefinition] parameter, or a scope value
     * representing a Presentation Definition is not present.
     */
    @SerialName("presentation_definition_uri")
    val presentationDefinitionUrl: String? = null,

    /**
     * OID4VP: dcql_query: A string containing a JSON-encoded DCQL query as defined in Section 6.
     */
    @SerialName("dcql_query")
    @Serializable(with = DCQLQueryStringTransformingSerializer::class)
    val dcqlQuery: DCQLQuery? = null,


    /**
     * RFC9396: The request parameter `authorization_details` contains, in JSON notation, an array of objects.
     * Each JSON object contains the data to specify the authorization requirements for a certain type of resource.
     * The type of resource or access requirement is determined by the [AuthorizationDetails.type] field.
     *
     * OID4VCI: This parameter MUST be used to convey th details about the Credentials the Wallet wants to obtain.
     * This specification introduces a new authorization details type `openid_credential`.
     */
    @SerialName("authorization_details")
    val authorizationDetails: Set<AuthorizationDetails>? = null,

    /**
     * OID4VP: OPTIONAL. String containing the Wallet's identifier. The Credential Issuer can use the discovery process
     * defined in SIOPv2 to determine the Wallet's capabilities and endpoints, using the `wallet_issuer` value as the
     * Issuer Identifier referred to in SIOPv2. This is RECOMMENDED in Dynamic Credential Requests.
     */
    @SerialName("wallet_issuer")
    val walletIssuer: String? = null,

    /**
     * OID4VP: OPTIONAL. String containing an opaque End-User hint that the Wallet MAY use in subsequent callbacks to
     * optimize the End-User's experience. This is RECOMMENDED in Dynamic Credential Requests.
     */
    @SerialName("user_hint")
    val userHint: String? = null,

    /**
     * OID4VP: OPTIONAL. String value identifying a certain processing context at the Credential Issuer. A value for
     * this parameter is typically passed in a Credential Offer from the Credential Issuer to the Wallet. This request
     * parameter is used to pass the issuer_state value back to the Credential Issuer.
     */
    @SerialName("issuer_state")
    val issuerState: String? = null,

    /**
     * OAuth 2.0 Responses: OPTIONAL. Informs the Authorization Server of the mechanism to be used for returning
     * Authorization Response parameters from the Authorization Endpoint. This use of this parameter is NOT RECOMMENDED
     * with a value that specifies the same Response Mode as the default Response Mode for the Response Type used.
     *
     * OIDC SIOPv2: This response mode `post` is used to request the Self-Issued OP to deliver the result of the
     * authentication process to a certain endpoint using the HTTP POST method.
     */
    @SerialName("response_mode")
    val responseMode: OpenIdConstants.ResponseMode? = null,

    /**
     * OID4VP: OPTIONAL. The Response URI to which the Wallet MUST send the Authorization Response using an HTTPS POST
     * request as defined by the Response Mode `direct_post`. The Response URI receives all Authorization Response
     * parameters as defined by the respective Response Type. When the `response_uri` parameter is present,
     * the `redirect_uri` Authorization Request parameter MUST NOT be present. If the `redirect_uri` Authorization
     * Request parameter is present when the Response Mode is `direct_post`, the Wallet MUST return an
     * `invalid_request` Authorization Response error.
     */
    @SerialName("response_uri")
    override val responseUrl: String? = null,

    /**
     * OAuth 2.0 JAR: If signed, the Authorization Request Object SHOULD contain the Claims `iss` (issuer) and `aud`
     * (audience) as members with their semantics being the same as defined in the JWT (RFC7519) specification. The
     * value of `aud` should be the value of the authorization server (AS) `issuer`, as defined in RFC 8414.
     */
    @SerialName("aud")
    override val audience: String? = null,

    /**
     * OAuth 2.0 JAR: If signed, the Authorization Request Object SHOULD contain the Claims `iss` (issuer) and `aud`
     * (audience) as members with their semantics being the same as defined in the JWT (RFC7519) specification. The
     * value of `aud` should be the value of the authorization server (AS) `issuer`, as defined in RFC 8414.
     */
    @SerialName("iss")
    override val issuer: String? = null,

    /**
     * OPTIONAL. Time at which the request was issued.
     */
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant? = null,

    /**
     * RFC8707: In requests to the authorization server, a client MAY indicate the protected resource (a.k.a.
     * resource server, application, API, etc.) to which it is requesting access. Its value MUST be an absolute URI,
     * as specified by Section 4.3 of (RFC3986).
     */
    @SerialName("resource")
    val resource: String? = null,

    /**
     * RFC7636: A challenge derived from the code verifier that is sent in the authorization request, to be verified
     * against later.
     */
    @SerialName("code_challenge")
    val codeChallenge: String? = null,

    /**
     * RFC7636: A method that was used to derive code challenge.
     */
    @SerialName("code_challenge_method")
    val codeChallengeMethod: String? = null,

    /**
     * CSC: Optional
     * Request a preferred language according to RFC 5646
     */
    @SerialName("lang")
    val lang: String? = null,

    /**
     * CSC: REQUIRED-"credential"
     * The identifier associated to the credential to authorize.
     * This parameter value may contain characters that are reserved, unsafe or
     * forbidden in URLs and therefore SHALL be url-encoded by the signature
     * application
     */
    @SerialName("credentialID")
    @Serializable(ByteArrayBase64UrlSerializer::class)
    val credentialID: ByteArray? = null,

    /**
     * CSC: Required-"credential"
     * This parameter contains the symbolic identifier determining the kind of
     * signature to be created
     */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,

    /**
     * CSC: Required-"credential"
     * The number of signatures to authorize
     */
    @SerialName("numSignatures")
    val numSignatures: Int? = null,

    /**
     * CSC: REQUIRED-"credential"
     * One or more base64url-encoded hash values to be signed
     */
    @SerialName("hashes")
    @Serializable(HashesSerializer::class)
    val hashes: Hashes? = null,

    /**
     * CSC: REQUIRED-"credential"
     * String containing the OID of the hash algorithm used to generate the hashes
     */
    @SerialName("hashAlgorithmOID")
    val hashAlgorithmOid: ObjectIdentifier? = null,

    /**
     * CSC: OPTIONAL
     * A free form description of the authorization transaction in the lang language.
     * The maximum size of the string is 500 characters
     */
    @SerialName("description")
    val description: String? = null,

    /**
     * CSC: OPTIONAL
     * To restrict access to the authorization server of a remote service, this specification introduces the
     * additional account_token parameter to be used when calling the oauth2/authorize endpoint. This
     * parameter contains a secure token designed to authenticate the authorization request based on an
     * Account ID that SHALL be uniquely assigned by the signature application to the signing user or to the
     * user’s application account
     */
    @SerialName("account_token")
    val accountToken: JsonWebToken? = null,

    /**
     * CSC: OPTIONAL
     * Arbitrary data from the signature application. It can be used to handle a
     * transaction identifier or other application-spe cific data that may be useful for
     * debugging purposes
     */
    @SerialName("clientData")
    val clientData: String? = null,

    /**
     * OID4VP: OPTIONAL. Array of strings, where each string is a base64url encoded JSON object that contains a typed
     * parameter set with details about the transaction that the Verifier is requesting the End-User to authorize.
     * The Wallet MUST return an error if a request contains even one unrecognized transaction data type or transaction
     * data not conforming to the respective type definition.
     */
    @SerialName("transaction_data")
    override val transactionData: Set<String>? = null,
) : RequestParameters {
    fun serialize() = odcJsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as AuthenticationRequestParameters

        if (responseType != other.responseType) return false
        if (clientId != other.clientId) return false
        if (redirectUrl != other.redirectUrl) return false
        if (scope != other.scope) return false
        if (state != other.state) return false
        if (nonce != other.nonce) return false
        if (walletNonce != other.walletNonce) return false
        if (claims != other.claims) return false
        if (clientMetadata != other.clientMetadata) return false
        if (clientMetadataUri != other.clientMetadataUri) return false
        if (idTokenHint != other.idTokenHint) return false
        if (request != other.request) return false
        if (requestUri != other.requestUri) return false
        if (requestUriMethod != other.requestUriMethod) return false
        if (idTokenType != other.idTokenType) return false
        if (presentationDefinition != other.presentationDefinition) return false
        if (presentationDefinitionUrl != other.presentationDefinitionUrl) return false
        if (dcqlQuery != other.dcqlQuery) return false
        if (authorizationDetails != other.authorizationDetails) return false
        if (walletIssuer != other.walletIssuer) return false
        if (userHint != other.userHint) return false
        if (issuerState != other.issuerState) return false
        if (responseMode != other.responseMode) return false
        if (responseUrl != other.responseUrl) return false
        if (audience != other.audience) return false
        if (issuer != other.issuer) return false
        if (issuedAt != other.issuedAt) return false
        if (resource != other.resource) return false
        if (codeChallenge != other.codeChallenge) return false
        if (codeChallengeMethod != other.codeChallengeMethod) return false
        if (lang != other.lang) return false
        if (credentialID != null) {
            if (other.credentialID == null) return false
            if (!credentialID.contentEquals(other.credentialID)) return false
        } else if (other.credentialID != null) return false
        if (signatureQualifier != other.signatureQualifier) return false
        if (numSignatures != other.numSignatures) return false
        if (!hashes.contentEquals(other.hashes)) return false
        if (hashAlgorithmOid != other.hashAlgorithmOid) return false
        if (description != other.description) return false
        if (accountToken != other.accountToken) return false
        if (clientData != other.clientData) return false
        if (transactionData != other.transactionData) return false

        return true
    }

    override fun hashCode(): Int {
        var result = responseType?.hashCode() ?: 0
        result = 31 * result + (clientId?.hashCode() ?: 0)
        result = 31 * result + (redirectUrl?.hashCode() ?: 0)
        result = 31 * result + (scope?.hashCode() ?: 0)
        result = 31 * result + (state?.hashCode() ?: 0)
        result = 31 * result + (nonce?.hashCode() ?: 0)
        result = 31 * result + (walletNonce?.hashCode() ?: 0)
        result = 31 * result + (claims?.hashCode() ?: 0)
        result = 31 * result + (clientMetadata?.hashCode() ?: 0)
        result = 31 * result + (clientMetadataUri?.hashCode() ?: 0)
        result = 31 * result + (idTokenHint?.hashCode() ?: 0)
        result = 31 * result + (request?.hashCode() ?: 0)
        result = 31 * result + (requestUri?.hashCode() ?: 0)
        result = 31 * result + (requestUriMethod?.hashCode() ?: 0)
        result = 31 * result + (idTokenType?.hashCode() ?: 0)
        result = 31 * result + (presentationDefinition?.hashCode() ?: 0)
        result = 31 * result + (presentationDefinitionUrl?.hashCode() ?: 0)
        result = 31 * result + (dcqlQuery?.hashCode() ?: 0)
        result = 31 * result + (authorizationDetails?.hashCode() ?: 0)
        result = 31 * result + (walletIssuer?.hashCode() ?: 0)
        result = 31 * result + (userHint?.hashCode() ?: 0)
        result = 31 * result + (issuerState?.hashCode() ?: 0)
        result = 31 * result + (responseMode?.hashCode() ?: 0)
        result = 31 * result + (responseUrl?.hashCode() ?: 0)
        result = 31 * result + (audience?.hashCode() ?: 0)
        result = 31 * result + (issuer?.hashCode() ?: 0)
        result = 31 * result + (issuedAt?.hashCode() ?: 0)
        result = 31 * result + (resource?.hashCode() ?: 0)
        result = 31 * result + (codeChallenge?.hashCode() ?: 0)
        result = 31 * result + (codeChallengeMethod?.hashCode() ?: 0)
        result = 31 * result + (lang?.hashCode() ?: 0)
        result = 31 * result + (credentialID?.contentHashCode() ?: 0)
        result = 31 * result + (signatureQualifier?.hashCode() ?: 0)
        result = 31 * result + (numSignatures ?: 0)
        result = 31 * result + (hashes?.contentHashCode() ?: 0)
        result = 31 * result + (hashAlgorithmOid?.hashCode() ?: 0)
        result = 31 * result + (description?.hashCode() ?: 0)
        result = 31 * result + (accountToken?.hashCode() ?: 0)
        result = 31 * result + (clientData?.hashCode() ?: 0)
        result = 31 * result + (transactionData?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            odcJsonSerializer.decodeFromString<AuthenticationRequestParameters>(it)
        }.wrap()
    }

}

