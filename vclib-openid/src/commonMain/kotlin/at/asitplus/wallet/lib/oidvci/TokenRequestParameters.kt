package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TokenRequestParameters(
    /**
     * RFC6749:
     * REQUIRED. Value MUST be set to "authorization_code".
     */
    @SerialName("grant_type")
    val grantType: String,

    /**
     * RFC6749:
     * REQUIRED. The authorization code received from the authorization server.
     */
    @SerialName("code")
    val code: String,

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
     * OID4VCI:
     * CONDITIONAL. The code representing the authorization to obtain Credentials of a certain type.
     */
    @SerialName("pre-authorized_code")
    val preAuthorizedCode: String? = null,

    /**
     * TODO
     */
    @SerialName("code_verifier")
    val codeVerifier: String? = null,

    /**
     * OID4VCI:
     * OPTIONAL. String value containing a user PIN. This value MUST be present if user_pin_required was set to true in
     * the Credential Offer. The string value MUST consist of maximum 8 numeric characters (the numbers 0 - 9).
     * This parameter MUST only be used, if the grant_type is urn:ietf:params:oauth:grant-type:pre-authorized_code.
     */
    @SerialName("user_pin")
    val userPin: String? = null,
)