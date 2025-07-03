package at.asitplus.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Duration

@Serializable
data class TokenResponseParameters(
    /**
     * RFC6749:
     * REQUIRED. The access token issued by the authorization server.
     */
    @SerialName("access_token")
    val accessToken: String,

    /**
     * RFC6749:
     * OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same authorization grant.
     */
    @SerialName("refresh_token")
    val refreshToken: String? = null,

    /**
     * RFC6749:
     * REQUIRED. The type of the token issued as described in Section 7.1.  Value is case insensitive.
     */
    @SerialName("token_type")
    val tokenType: String,

    /**
     * RFC6749:
     * RECOMMENDED. The lifetime in seconds of the access token.  For example, the value "3600" denotes that the access
     * token will expire in one hour from the time the response was generated. If omitted, the authorization server
     * SHOULD provide the expiration time via other means or document the default value.
     */
    @SerialName("expires_in")
    @Serializable(with = DurationSecondsIntSerializer::class)
    val expires: Duration? = null,

    /**
     * RFC6749:
     * OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED.
     */
    @SerialName("scope")
    val scope: String? = null,

    /**
     * OID4VCI:
     * OPTIONAL String containing a nonce to be used to create a proof of possession of key material when requesting a
     * Credential. When received, the Wallet MUST use this nonce value for its subsequent credential requests until the
     * Credential Issuer provides a fresh nonce.
     */
    @SerialName("c_nonce")
    @Deprecated("Removed in OID4VCI draft 14, see ClientNonceResponse")
    val clientNonce: String? = null,

    /**
     * OID4VCI:
     * OPTIONAL, In the Pre-Authorized Code Flow, the Token Request is still pending as the Credential Issuer is waiting
     * for the End-User interaction to complete. The client SHOULD repeat the Token Request. Before each new request,
     * the client MUST wait at least the number of seconds specified by the interval response parameter.
     */
    @SerialName("authorization_pending")
    val authorizationPending: Boolean? = null,

    /**
     * OID4VCI:
     * OPTIONAL, the minimum amount of time in seconds that the client SHOULD wait between polling requests to the Token
     * Endpoint in the Pre-Authorized Code Flow. If no value is provided, clients MUST use 5 as the default.
     */
    @SerialName("interval")
    @Serializable(with = DurationSecondsIntSerializer::class)
    val interval: Duration? = null,

    /**
     * OID4VP: REQUIRED when `authorization_details` parameter is used to request issuance of a certain Credential type.
     * It MUST NOT be used otherwise.
     */
    @SerialName("authorization_details")
    val authorizationDetails: Set<AuthorizationDetails>? = null,

    /**
     * CSC: OPTIONAL
     * The identifier associated to the credential authorized in the corresponding authorization
     * request. This response parameter MAY be present in case the scope credential is used
     * in the authorization request along with the parameter “signatureQualifier” and the
     * authorization server determined a credentialID in the authorization process to be used
     * in subsequent signature operations.
     */
    @SerialName("credentialID")
    val credentialId: String? = null,
) {

    fun toHttpHeaderValue() = "$tokenType $accessToken"
    fun toHttpHeader() = "${HttpHeaders.Authorization}: $tokenType $accessToken"

    fun serialize() = odcJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<TokenResponseParameters> =
            catching { odcJsonSerializer.decodeFromString<TokenResponseParameters>(input) }
    }
}