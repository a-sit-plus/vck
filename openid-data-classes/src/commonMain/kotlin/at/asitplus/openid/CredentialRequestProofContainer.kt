package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
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
    val jwt: Set<String>? = null,

    /**
     * A JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) representing a key attestation without using a
     * proof of possession of the cryptographic key material that is being attested.
     * When a `proofs` object is using an attestation proof type, the object MUST include an `attestation` parameter
     * with its value being an array that contains exactly one JWT that is formed as defined in Appendix D.1.
     * See [attestationParsed].
     */
    @SerialName("attestation")
    val attestation: Set<String>? = null,
) {

    val jwtParsed: Collection<JwsSigned<JsonWebToken>>? by lazy {
        jwt?.mapNotNull {
            JwsSigned.deserialize<JsonWebToken>(JsonWebToken.serializer(), it, joseCompliantSerializer).getOrNull()
        }
    }

    val attestationParsed: Collection<JwsSigned<KeyAttestationJwt>>? by lazy {
        attestation?.mapNotNull {
            JwsSigned.deserialize<KeyAttestationJwt>(KeyAttestationJwt.serializer(), it, joseCompliantSerializer).getOrNull()
        }
    }
}