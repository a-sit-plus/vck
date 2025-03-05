package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialRequestProof(
    /**
     * OID4VCI: e.g. `jwt`, or `ldp_vp`. See [at.asitplus.openid.OpenIdConstants.ProofType].
     */
    @SerialName("proof_type")
    val proofType: OpenIdConstants.ProofType,

    /**
     * OID4VCI: A JWT (RFC7519) is used as proof of possession. When [proofType] is `jwt`, a proof object MUST include
     * a `jwt` claim containing a JWT defined in Section 8.2.1.1.
     * See [jwtParsed].
     */
    @SerialName("jwt")
    val jwt: String? = null,

    /**
     * OID4VCI: A JWT (RFC7519) is used as proof of possession. When [proofType] is set to `attestation`, the object
     * MUST also contain an `attestation` parameter that includes a JWT as defined in Section 8.2.1.3.
     * See [attestationParsed].
     */
    @SerialName("attestation")
    val attestation: String? = null,
) {
    val jwtParsed: JwsSigned<JsonWebToken>? by lazy {
        jwt?.let { JwsSigned.deserialize<JsonWebToken>(JsonWebToken.serializer(), it, odcJsonSerializer).getOrNull() }
    }

    val attestationParsed: JwsSigned<KeyAttestationJwt>? by lazy {
        attestation?.let { JwsSigned.deserialize<KeyAttestationJwt>(KeyAttestationJwt.serializer(), it, odcJsonSerializer).getOrNull() }
    }
}