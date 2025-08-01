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
     */
    @SerialName("resource")
    val resource: String? = null,

    /**
     * RFC6749: OPTIONAL. The refresh token issued to the client.
     */
    @SerialName("refresh_token")
    val refreshToken: String? = null,

    /**
     * RFC6749:
     * REQUIRED, if the "redirect_uri" parameter was included in the authorization request,
     * and their values MUST be identical.
     */
    @SerialName("redirect_uri")
    val redirectUrl: String,

    /**
     * RFC6749:
     * REQUIRED, if the client is not authenticating with the authorization server.
     */
    @SerialName("client_id")
    val clientId: String,

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