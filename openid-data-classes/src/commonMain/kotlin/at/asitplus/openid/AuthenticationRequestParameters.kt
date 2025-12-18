package at.asitplus.openid

import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.csc.Hashes
import at.asitplus.csc.serializers.HashesSerializer
import at.asitplus.csc.enums.SignatureQualifier
import at.asitplus.csc.contentEquals
import at.asitplus.csc.contentHashCode
import at.asitplus.iso.serializeOrigin
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import kotlin.time.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * Contents of an OIDC Authentication Request.
 *
 * Usually, these parameters are appended to the Authorization Endpoint URL of the OpenId Provider (maybe the
 * Wallet App in case of OpenID4VP, or the Credential Issuer for OID4VCI).
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
    val responseType: String? = null,

    /**
     * OID4VP 1.0: REQUIRED. As in OIDC
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
     * OIDC: REQUIRED. Redirection URI to which the response will be sent. This URI MUST exactly match one of the
     * Redirection URI values for the Client pre-registered at the OpenID Provider, with the matching performed as
     * described in Section 6.2.1 of RFC3986 (Simple String Comparison).
     *
     * Optional when JAR (RFC9101) is used.
     *
     * See also [redirectUrlExtracted]
     */
    @SerialName("redirect_uri")
    val redirectUrl: String? = null,

    /**
     * OID4VP 1.0: OPTIONAL
     * OIDC: REQUIRED. OpenID Connect requests MUST contain the openid scope value. If the openid scope value is not
     * present, the behavior is entirely unspecified. Other scope values MAY be present. Scope values used that are not
     * understood by an implementation SHOULD be ignored.
     * e.g. `profile` or `com.example.healthCardCredential`
     */
    @SerialName("scope")
    val scope: String? = null,

    /**
     * OID4VP 1.0: OPTIONAL.
     * OIDC: RECOMMENDED. Opaque value used to maintain state between the request and the callback. Typically,
     * Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this
     * parameter with a browser cookie.
     */
    @SerialName("state")
    val state: String? = null,

    /**
     * OID4VP 1.0: REQUIRED.
     * OIDC: OPTIONAL.
     * String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
     * The value is passed through unmodified from the Authentication Request to the ID Token. Sufficient entropy MUST
     * be present in the nonce values used to prevent attackers from guessing values.
     */
    @SerialName("nonce")
    val nonce: String? = null,

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
     *
     * OID4VP 1.0: OPTIONAL. Authoritative data the Wallet is able to obtain about the
     * Client from other sources, for example those from an OpenID Federation
     * Entity Statement, take precedence over the values passed in client_metadata.
     */
    @SerialName("client_metadata")
    val clientMetadata: RelyingPartyMetadata? = null,

    /**
     * OIDC: OPTIONAL. ID Token previously issued by the Authorization Server being passed as a hint about the
     * End-User's current or past authenticated session with the Client. If the End-User identified by the ID Token is
     * logged in or is logged in by the request, then the Authorization Server returns a positive response; otherwise,
     * it SHOULD return an error, such as login_required.
     */
    @SerialName("id_token_hint")
    val idTokenHint: String? = null,

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
     * OID4VP 1.0: A JSON object containing a DCQL query as defined in
     * [Section 6](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#dcql_query).
     * Either a [dcqlQuery] or a [scope] parameter representing a DCQL Query MUST be present in the Authorization
     * Request, but not both.
     */
    @SerialName("dcql_query")
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
     * parameter is used to pass the `issuer_state` value back to the Credential Issuer, see
     * [CredentialOfferGrantsAuthCode.issuerState].
     */
    @SerialName("issuer_state")
    val issuerState: String? = null,

    /**
     * OID4VP 1.0: REQUIRED (Defined as in OAuth2.0 Responses)
     *
     * OAuth 2.0 Responses: OPTIONAL. Informs the Authorization Server of the mechanism to be used for returning
     * Authorization Response parameters from the Authorization Endpoint. This use of this parameter is NOT RECOMMENDED
     * with a value that specifies the same Response Mode as the default Response Mode for the Response Type used.
     *
     * OIDC SIOPv2: This response mode `post` is used to request the Self-Issued OP to deliver the result of the
     * authentication process to a certain endpoint using the HTTP POST method.
     *
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
    val responseUrl: String? = null,

    /**
     * OAuth 2.0 JAR: If signed, the Authorization Request Object SHOULD contain the Claims `iss` (issuer) and `aud`
     * (audience) as members with their semantics being the same as defined in the JWT (RFC7519) specification. The
     * value of `aud` should be the value of the authorization server (AS) `issuer`, as defined in RFC 8414.
     */
    @SerialName("aud")
    val audience: String? = null,

    /**
     * OAuth 2.0 JAR: If signed, the Authorization Request Object SHOULD contain the Claims `iss` (issuer) and `aud`
     * (audience) as members with their semantics being the same as defined in the JWT (RFC7519) specification. The
     * value of `aud` should be the value of the authorization server (AS) `issuer`, as defined in RFC 8414.
     *
     * OpenID4VP 1.0: The iss claim MAY be present in the Request Object. However, even if it is present, the Wallet MUST ignore it
     */
    @SerialName("iss")
    val issuer: String? = null,

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
    @Serializable(with = ObjectIdentifierStringSerializer::class)
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
     * transaction identifier or other application-specific data that may be useful for
     * debugging purposes
     */
    @SerialName("clientData")
    val clientData: String? = null,

    /**
     * OID4VP 1.0: OPTIONAL. Non-empty array of strings, where each string is a base64url-encoded JSON object that contains
     * a typed parameter set with details about the transaction that the Verifier is requesting
     * the End-User to authorize. The Wallet MUST return an error if a request contains even one unrecognized
     * transaction data type or transaction data not conforming to the respective type definition.
     */
    @SerialName("transaction_data")
    val transactionData: List<TransactionDataBase64Url>? = null,

    /**
     * DCAPI: REQUIRED when signed requests defined in Appendix A.3.2 are used with the Digital
     * Credentials API (DC API). An array of strings, each string representing an Origin of the
     * Verifier that is making the request. The Wallet MUST compare values in this parameter to the
     * Origin to detect replay of the request from a malicious Verifier. If the Origin does not
     * match any of the entries in expected_origins, the Wallet MUST return an error. This error
     * SHOULD be an invalid_request error. This parameter is not for use in unsigned requests and
     * therefore a Wallet MUST ignore this parameter if it is present in an unsigned request.
     */
    @SerialName("expected_origins")
    val expectedOrigins: List<String>? = null,

    /**
     * OID4VP 1.0: OPTIONAL.
     * A non-empty array of attestations about the Verifier relevant to the Credential Request.
     * These attestations MAY include Verifier metadata, policies, trust status, or authorizations.
     * Attestations are intended to support authorization decisions, inform Wallet policy enforcement, or enrich the
     * End-User consent dialog
     */
    @SerialName("verifier_info")
    val verifierInfo: List<VerifierInfo>? = null
) : RequestParameters() {

    /**
     * Reads the [OpenIdConstants.ClientIdScheme] by extracting the prefix from [clientId]
     */
    val clientIdSchemeExtracted: OpenIdConstants.ClientIdScheme?
        get() = clientId?.let { OpenIdConstants.ClientIdScheme.decodeFromClientId(it) }

    /**
     * Reads the [clientId] and removes the prefix of the [clientIdSchemeExtracted].
     * OpenID4VP states that the *full* [clientId] must be used for presentations and anything else.
     */
    val clientIdWithoutPrefix: String?
        get() = clientId?.let { clientId ->
            clientIdSchemeExtracted?.let { clientId.removePrefix("${it.stringRepresentation}:") }
        }

    /**
     * Reads the [redirectUrl], or the [clientIdWithoutPrefix] if [clientIdSchemeExtracted] is
     * [OpenIdConstants.ClientIdScheme.RedirectUri].
     */
    val redirectUrlExtracted: String?
        get() = redirectUrl
            ?: (clientIdSchemeExtracted as? OpenIdConstants.ClientIdScheme.RedirectUri)?.let { clientIdWithoutPrefix }

    fun verifyExpectedOrigin(actualOrigin: String): Boolean {
        val expected = expectedOrigins ?: return false
        val actualSerialized = actualOrigin.serializeOrigin() ?: return false
        return expected.any { it.serializeOrigin() == actualSerialized }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as AuthenticationRequestParameters

        if (numSignatures != other.numSignatures) return false
        if (responseType != other.responseType) return false
        if (clientId != other.clientId) return false
        if (redirectUrl != other.redirectUrl) return false
        if (scope != other.scope) return false
        if (state != other.state) return false
        if (nonce != other.nonce) return false
        if (walletNonce != other.walletNonce) return false
        if (claims != other.claims) return false
        if (clientMetadata != other.clientMetadata) return false
        if (idTokenHint != other.idTokenHint) return false
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
        if (!credentialID.contentEquals(other.credentialID)) return false
        if (signatureQualifier != other.signatureQualifier) return false
        if (hashes != other.hashes) return false
        if (hashAlgorithmOid != other.hashAlgorithmOid) return false
        if (description != other.description) return false
        if (accountToken != other.accountToken) return false
        if (clientData != other.clientData) return false
        if (transactionData != other.transactionData) return false
        if (expectedOrigins != other.expectedOrigins) return false
        if (verifierInfo != other.verifierInfo) return false

        return true
    }

    override fun hashCode(): Int {
        var result = numSignatures ?: 0
        result = 31 * result + (responseType?.hashCode() ?: 0)
        result = 31 * result + (clientId?.hashCode() ?: 0)
        result = 31 * result + (redirectUrl?.hashCode() ?: 0)
        result = 31 * result + (scope?.hashCode() ?: 0)
        result = 31 * result + (state?.hashCode() ?: 0)
        result = 31 * result + (nonce?.hashCode() ?: 0)
        result = 31 * result + (walletNonce?.hashCode() ?: 0)
        result = 31 * result + (claims?.hashCode() ?: 0)
        result = 31 * result + (clientMetadata?.hashCode() ?: 0)
        result = 31 * result + (idTokenHint?.hashCode() ?: 0)
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
        result = 31 * result + (hashes?.hashCode() ?: 0)
        result = 31 * result + (hashAlgorithmOid?.hashCode() ?: 0)
        result = 31 * result + (description?.hashCode() ?: 0)
        result = 31 * result + (accountToken?.hashCode() ?: 0)
        result = 31 * result + (clientData?.hashCode() ?: 0)
        result = 31 * result + (transactionData?.hashCode() ?: 0)
        result = 31 * result + (expectedOrigins?.hashCode() ?: 0)
        result = 31 * result + (verifierInfo?.hashCode() ?: 0)
        return result
    }


}

