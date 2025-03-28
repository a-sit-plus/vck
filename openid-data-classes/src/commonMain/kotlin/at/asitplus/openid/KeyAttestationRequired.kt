package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class KeyAttestationRequired(
    /**
     * OID4VCI: OPTIONAL. Array defining values specified in Appendix D.2 accepted by the Credential Issuer.
     */
    @SerialName("key_storage")
    val keyStorage: Collection<String>? = null,

    /**
     * OID4VCI: OPTIONAL. Array defining values specified in Appendix D.2 accepted by the Credential Issuer.
     */
    @SerialName("user_authentication")
    val userAuthentication: Collection<String>? = null,
)