package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialOfferGrantsAuthCode(
    /**
     * OID4VCI: OPTIONAL. String value created by the Credential Issuer and opaque to the Wallet that is used to bind
     * the subsequent Authorization Request with the Credential Issuer to a context set up during previous steps. If the
     * Wallet decides to use the Authorization Code Flow and received a value for this parameter, it MUST include it in
     * the subsequent Authorization Request to the Credential Issuer as the `issuer_state` parameter value, see
     * [AuthenticationRequestParameters.issuerState].
     */
    @SerialName("issuer_state")
    val issuerState: String? = null,

    /**
     * OID4VCI: OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant
     * type when `authorization_servers` parameter in the Credential Issuer metadata has multiple entries. It MUST NOT
     * be used otherwise. The value of this parameter MUST match with one of the values in the `authorization_servers`
     * array obtained from the Credential Issuer metadata.
     */
    @SerialName("authorization_server")
    val authorizationServer: String? = null,
)