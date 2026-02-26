package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

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

    /**
     * OPTIONAL. A duration specifying a PID or Attestation Provider's preference for the remaining validity period of the WUA it receives during issuance, in seconds.
     * A Wallet Provider SHALL ensure that a Wallet Unit can always present a WUA with a remaining validity period of at least 31 days for their WSCD.
     * See: https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md
     */
    @SerialName("preferred_ttl")
    @Serializable(with = DurationSecondsIntSerializer::class)
    val preferredTtl: Duration? = 31.days
)