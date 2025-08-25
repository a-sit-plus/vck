package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TokenRequestParameters(
    /**
     * RFC6749: REQUIRED. Value MUST be set to `authorization_code`.
     *
     * OID4VCI: May be `urn:ietf:params:oauth:grant-type:pre-authorized_code`.
     */
    @SerialName("grant_type")
    val grantType: String,

    /**
     * RFC6749: REQUIRED. The authorization code received from the authorization server.
     */
    @SerialName("code")
    val code: String? = null,

    /**
     * RFC6749: OPTIONAL. The authorization and token endpoints allow the client to specify the
     * scope of the access request using the "scope" request parameter.  In
     * turn, the authorization server uses the "scope" response parameter to
     * inform the client of the scope of the access token issued.
     */
    @SerialName("scope")
    val scope: String? = null,

    /**
     * RFC8707: When requesting a token, the client can indicate the desired target service(s) where it intends to use
     * that token by way of the [resource] parameter and can indicate the desired scope of the requested token using the
     * [scope] parameter.
     *
     * RFC8693: Optional URI that indicates the target service or resource where the client intends to use the requested
     * security token. This enables the authorization server to apply policy as appropriate for the target, such as
     * determining the type and content of the token to be issued or if and how the token is to be encrypted.
     */
    @SerialName("resource")
    val resource: String? = null,

    /**
     * RFC8693: Optional logical name of the target service where the client intends to use the requested security
     * token. This serves a purpose similar to the resource parameter but with the client providing a logical name for
     * the target service.
     */
    @SerialName("audience")
    val audience: String? = null,

    /**
     * RFC8693: Optional identifier for the type of the requested security token. If the requested type is unspecified,
     * the issued token type is at the discretion of the authorization server and may be dictated by knowledge of the
     * requirements of the service or resource indicated by the resource or audience parameter.
     */
    @SerialName("requested_token_type")
    val requestedTokenType: String? = null,

    /**
     * RFC8693: Required security token that represents the identity of the party on behalf of whom the request is
     * being made. Typically, the subject of this token will be the subject of the security token issued in response
     * to the request.
     */
    @SerialName("subject_token")
    val subjectToken: String? = null,

    /**
     * RFC8693: Required identifier that indicates the type of the security token in the subject_token parameter.
     */
    @SerialName("subject_token_type")
    val subjectTokenType: String? = null,

    /**
     * RFC8693: Optional security token that represents the identity of the acting party. Typically, this will be the
     * party that is authorized to use the requested security token and act on behalf of the subject.
     */
    @SerialName("actor_token")
    val actorToken: String? = null,

    /**
     * RFC8693: An identifier that indicates the type of the security token in the [actorToken] parameter.
     * This is REQUIRED when the [actorToken] parameter is present in the request but MUST NOT be included otherwise.
     */
    @SerialName("actor_token_type")
    val actorTokenType: String? = null,

    /**
     * RFC6749: OPTIONAL. The refresh token issued to the client.
     */
    @SerialName("refresh_token")
    val refreshToken: String? = null,

    /**
     * RFC6749: REQUIRED, if the `redirect_uri` parameter was included in the authorization request,
     * and their values MUST be identical.
     */
    @SerialName("redirect_uri")
    val redirectUrl: String? = null,

    /**
     * RFC6749: REQUIRED, if the client is not authenticating with the authorization server.
     */
    @SerialName("client_id")
    val clientId: String? = null,

    /**
     * OID4VCI: Credential Issuers MAY support requesting authorization to issue a Credential using this parameter.
     * The request parameter `authorization_details` defined in Section 2 of `RFC9396` MUST be used to convey the
     * details about the Credentials the Wallet wants to obtain.
     */
    @SerialName("authorization_details")
    val authorizationDetails: Set<AuthorizationDetails>? = null,

    /**
     * OID4VCI: The code representing the authorization to obtain Credentials of a certain type.
     * This parameter MUST be present if [grantType] is `urn:ietf:params:oauth:grant-type:pre-authorized_code`.
     */
    @SerialName("pre-authorized_code")
    val preAuthorizedCode: String? = null,

    /**
     * OID4VCI: OPTIONAL. String value containing a Transaction Code. This value MUST be present if a `tx_code` object
     * was present in the Credential Offer (including if the object was empty).
     * This parameter MUST only be used if the [grantType] is `urn:ietf:params:oauth:grant-type:pre-authorized_code`.
     */
    @SerialName("tx_code")
    val transactionCode: String? = null,

    /**
     * RFC7636: A cryptographically random string that is used to correlate the authorization request to the token
     * request.
     */
    @SerialName("code_verifier")
    val codeVerifier: String? = null,

    /**
     * CSC: OPTIONAL
     * Arbitrary data from the signature application. It can be used to handle a
     * transaction identifier or other application-spe cific data that may be useful for
     * debugging purposes
     */
    @SerialName("clientData")
    val clientData: String? = null,
)