package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialOfferGrantsPreAuthCode(
    /**
     * OID4VCI: REQUIRED. The code representing the Credential Issuer's authorization for the Wallet to obtain
     * Credentials of a certain type. This code MUST be short lived and single use. If the Wallet decides to use the
     * Pre-Authorized Code Flow, this parameter value MUST be included in the subsequent Token Request with the
     * Pre-Authorized Code Flow.
     */
    @SerialName("pre-authorized_code")
    val preAuthorizedCode: String,

    /**
     * OID4VCI: OPTIONAL. Object specifying whether the Authorization Server expects presentation of a Transaction Code
     * by the End-User along with the Token Request in a Pre-Authorized Code Flow. If the Authorization Server does not
     * expect a Transaction Code, this object is absent; this is the default.
     */
    @SerialName("tx_code")
    val transactionCode: CredentialOfferGrantsPreAuthCodeTransactionCode? = null,

    /**
     * OID4VCI: OPTIONAL. The minimum amount of time in seconds that the Wallet SHOULD wait between polling requests to
     * the token endpoint. If no value is provided, Wallets MUST use 5 as the default.
     */
    @SerialName("interval")
    val waitIntervalSeconds: Int? = 5,

    /**
     * OID4VCI: OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant
     * type when `authorization_servers` parameter in the Credential Issuer metadata has multiple entries.
     */
    @SerialName("authorization_server")
    val authorizationServer: String? = null
)