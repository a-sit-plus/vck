package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmOverloads
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

private val defaultPreferredTtl = 31.days

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
     * OPTIONAL. A duration specifying a PID or Attestation Provider's preference for the remaining status maintenance
     * period (`key_storage_status.exp` minus current time) of the KA it receives during issuancej
     * See
     * [EUDI TS3](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md#24-life-cycle)
     */
    @SerialName("preferred_key_storage_status_period")
    @Serializable(with = DurationSecondsIntSerializer::class)
    val preferredTtl: Duration? = defaultPreferredTtl,
) {
    /**
     * Java-safe constructor: Java can't call the primary constructor, because it takes the value class [Duration].
     */
    @JvmOverloads
    internal constructor(
        keyStorage: Collection<String>?,
        userAuthentication: Collection<String>? = null,
        preferredTtlSeconds: Long? = defaultPreferredTtl.inWholeSeconds,
    ) : this(
        keyStorage = keyStorage,
        userAuthentication = userAuthentication,
        preferredTtl = preferredTtlSeconds?.seconds,
    )

    /** Java-safe accessor for [preferredTtl], in seconds. */
    val preferredTtlSeconds: Long?
        get() = preferredTtl?.inWholeSeconds
}
