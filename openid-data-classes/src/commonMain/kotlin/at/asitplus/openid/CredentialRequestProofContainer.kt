package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactStringSerializer
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.signum.indispensable.josef.typed
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

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

    val jwtParsed: Collection<JwsCompactTyped<JsonWebToken>>? by lazy {
        jwt?.mapNotNull {
            runCatching<JwsCompactTyped<JsonWebToken>> { it.typed() }.getOrNull()
        }
    }

    val attestationParsed: Collection<JwsCompactTyped<KeyAttestationJwt>>? by lazy {
        attestation?.mapNotNull {
            runCatching<JwsCompactTyped<KeyAttestationJwt>> { it.typed() }.getOrNull()
        }
    }
}