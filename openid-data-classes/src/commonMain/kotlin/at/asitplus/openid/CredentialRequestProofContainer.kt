package at.asitplus.openid

import at.asitplus.catchingUnwrapped
import at.asitplus.openid.jwtpayload.KeyAttestationPayload
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactStringSerializer
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwtClaimNames
import at.asitplus.signum.indispensable.josef.JwtPayload
import at.asitplus.signum.indispensable.josef.typed
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class CredentialRequestProofContainer(
    /**
     * A JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) is used for proof of possession.
     * When a `proofs` object is using a `jwt` proof type, it MUST include a `jwt` parameter with its value being a
     * non-empty array of JWTs, where each JWT is formed as defined in Appendix F.1.
     * See [jwtParsed].
     */
    @SerialName("jwt")
    val jwt: Set<@Serializable(JwsCompactStringSerializer::class) JwsCompact>? = null,

    /**
     * A JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) representing a key attestation without using a
     * proof of possession of the cryptographic key material that is being attested.
     * When a `proofs` object is using an attestation proof type, the object MUST include an `attestation` parameter
     * with its value being an array that contains exactly one JWT that is formed as defined in Appendix D.1.
     * See [attestationParsed].
     */
    @SerialName("attestation")
    val attestation: Set<@Serializable(JwsCompactStringSerializer::class) JwsCompact>? = null,
) {
    data class JwtProofTypePayload(
        @SerialName(JwtClaimNames.IanaRegistered.ClaimNames.RFC7519.ISS)
        override val issuer: String? = null,
        @SerialName(JwtClaimNames.IanaRegistered.ClaimNames.RFC7519.AUD)
        override val audience: String,
        @SerialName(JwtClaimNames.IanaRegistered.ClaimNames.RFC7519.IAT)
        @Serializable(with = InstantLongSerializer::class)
        override val issuedAt: Instant,
        @SerialName(JwtClaimNames.IanaRegistered.ClaimNames.RFC9449.NONCE)
        val nonce: String? = null,
    ) : JwtPayload {
        override val subject: String? = null
        override val notBefore: Instant? = null
        override val expiration: Instant? = null
        override val jwtId: String? = null
    }

    val jwtParsed: Collection<JwsCompactTyped<JwtProofTypePayload>>? by lazy {
        jwt?.mapNotNull {
            catchingUnwrapped<JwsCompactTyped<JwtProofTypePayload>> { it.typed() }.getOrNull()
        }
    }

    val attestationParsed: Collection<JwsCompactTyped<KeyAttestationPayload>>? by lazy {
        attestation?.mapNotNull {
            catchingUnwrapped<JwsCompactTyped<KeyAttestationPayload>> { it.typed() }.getOrNull()
        }
    }
}