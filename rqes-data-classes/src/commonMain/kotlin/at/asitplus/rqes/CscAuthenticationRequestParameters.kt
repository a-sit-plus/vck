package at.asitplus.openid

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.rqes.Hashes
import at.asitplus.rqes.contentEquals
import at.asitplus.rqes.contentHashCode
import at.asitplus.rqes.enums.SignatureQualifierEnum
import at.asitplus.rqes.serializers.HashesSerializer
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.JsonWebToken
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString


//TODO Rework comments to fit CSC use-case
/**
 * Contents of an OIDC Authentication Request.
 *
 * Usually, these parameters are appended to the Authorization Endpoint URL of the OpenId Provider (maybe the
 * Wallet App in case of SIOPv2, or the Credential Issuer for OID4VCI).
 */
@Serializable
data class CscAuthenticationRequestParameters(
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
    val responseType: String,

    /**
     * OIDC: REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server.
     */
    @SerialName("client_id")
    val clientId: String,

    /**
     * OIDC: REQUIRED. Redirection URI to which the response will be sent. This URI MUST exactly match one of the
     * Redirection URI values for the Client pre-registered at the OpenID Provider, with the matching performed as
     * described in Section 6.2.1 of RFC3986 (Simple String Comparison).
     *
     * Optional when JAR (RFC9101) is used.
     */
    @SerialName("redirect_uri")
    val redirectUrl: String? = null,

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
    val state: String? = null,

    /**
     * OAuth 2.0 JAR: REQUIRED unless request is specified. The absolute URI, as defined by RFC3986, that is the
     * Request Object URI referencing the authorization request parameters stated in Section 4 of RFC6749 (OAuth 2.0).
     * If this parameter is present in the authorization request, `request` MUST NOT be present.
     */
    @SerialName("request_uri")
    val requestUri: String? = null,

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
     * RFC7636: A challenge derived from the code verifier that is sent in the authorization request, to be verified
     * against later.
     */
    @SerialName("code_challenge")
    val codeChallenge: String,

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
    val signatureQualifier: SignatureQualifierEnum? = null,

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
) : RequestParameters {

    fun serialize() = odcJsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CscAuthenticationRequestParameters

        if (responseType != other.responseType) return false
        if (clientId != other.clientId) return false
        if (redirectUrl != other.redirectUrl) return false
        if (scope != other.scope) return false
        if (state != other.state) return false
        if (requestUri != other.requestUri) return false
        if (authorizationDetails != other.authorizationDetails) return false
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

        return true
    }

    override fun hashCode(): Int {
        var result = responseType.hashCode()
        result = 31 * result + clientId.hashCode()
        result = 31 * result + (redirectUrl?.hashCode() ?: 0)
        result = 31 * result + (scope?.hashCode() ?: 0)
        result = 31 * result + (state?.hashCode() ?: 0)
        result = 31 * result + (requestUri?.hashCode() ?: 0)
        result = 31 * result + (authorizationDetails?.hashCode() ?: 0)
        result = 31 * result + codeChallenge.hashCode()
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
        return result
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            odcJsonSerializer.decodeFromString<AuthenticationRequestParameters>(it)
        }.wrap()
    }
}

