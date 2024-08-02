package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.oidc.jsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

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
     * OID4VP: TODO Definition
     * RFC9396
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
    val transactionCode: CredentialOfferGrantsPreAuthCodeTransactionCode? = null,

    /**
     * RFC7636: A cryptographically random string that is used to correlate the authorization request to the token
     * request.
     */
    @SerialName("code_verifier")
    val codeVerifier: String? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<TokenRequestParameters> =
            runCatching { jsonSerializer.decodeFromString<TokenRequestParameters>(input) }.wrap()
    }
}