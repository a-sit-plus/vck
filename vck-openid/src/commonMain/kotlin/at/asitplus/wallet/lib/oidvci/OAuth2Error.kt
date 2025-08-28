package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Source: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
 * OpenID for Verifiable Credential Issuance
 * Published: 3 February 2023
 */
@Serializable
data class OAuth2Error(
    @SerialName("error")
    val error: String,

    @SerialName("error_description")
    val errorDescription: String? = null,

    @SerialName("error_uri")
    val errorUri: String? = null,

    @SerialName("state")
    val state: String? = null
)