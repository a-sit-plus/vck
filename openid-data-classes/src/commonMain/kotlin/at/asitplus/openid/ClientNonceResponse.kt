package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ClientNonceResponse(
    /**
     * OID4VCI: REQUIRED. String containing a nonce to be used when creating a proof of possession of the key proof
     * (see [CredentialRequestProofContainer], see Section 8.2 of OID4VCI). This value MUST be unpredictable.
     */
    @SerialName("c_nonce")
    val clientNonce: String,
)