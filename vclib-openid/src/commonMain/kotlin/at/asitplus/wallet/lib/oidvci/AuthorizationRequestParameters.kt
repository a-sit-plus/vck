package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * To be sent from the Wallet to the Issuer
 */
@Serializable
data class AuthorizationRequestParameters(
    /**
     * e.g. `code`
     */
    @SerialName("response_type")
    val responseType: String,

    @SerialName("client_id")
    val clientId: String,

    @SerialName("authorization_details")
    val authorizationDetails: AuthorizationDetails? = null,

    @SerialName("redirect_uri")
    val redirectUrl: String,

    /**
     * e.g. `com.example.healthCardCredential`
     */
    @SerialName("scope")
    val scope: String? = null,

    /**
     * May contain the Wallet's OIDC issuer URL, for discovery.
     * Recommended in Dynamic Credential Request.
     */
    @SerialName("wallet_issuer")
    val walletIssuer: String? = null,

    /**
     * Recommended in Dynamic Credential Request
     */
    @SerialName("user_hint")
    val userHint: String? = null,

    @SerialName("issuer_state")
    val issuerState: String? = null,
)