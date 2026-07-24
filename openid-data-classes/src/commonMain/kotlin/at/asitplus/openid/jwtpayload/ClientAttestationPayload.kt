package at.asitplus.openid.jwtpayload

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant


/**
 * Defined in [draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-10)
 */
@Serializable
data class ClientAttestationPayload(
    @SerialName(ClaimNames.RFC7519.ISS)
    override val issuer: String? = null,
    @SerialName(ClaimNames.RFC7519.SUB)
    override val subject: String,
    @SerialName(ClaimNames.RFC7519.AUD)
    override val audience: String? = null,
    @SerialName(ClaimNames.RFC7519.NBF)
    @Serializable(with = InstantLongSerializer::class)
    override val notBefore: Instant? = null,
    @SerialName(ClaimNames.RFC7519.IAT)
    @Serializable(with = InstantLongSerializer::class)
    override val issuedAt: Instant? = null,
    @SerialName(ClaimNames.RFC7519.EXP)
    @Serializable(with = InstantLongSerializer::class)
    override val expiration: Instant,
    @SerialName(ClaimNames.RFC7519.JTI)
    override val jwtId: String? = null,
    /**
     * OID4VP: This claim contains the confirmation method as defined in RFC7800. It MUST contain a JWK as defined in
     * Section 3.2 of RFC7800. This claim determines the public key for which the corresponding private key the
     * Verifier MUST proof possession of when presenting the Verifier Attestation JWT. This additional security measure
     * allows the Verifier to obtain a Verifier Attestation JWT from a trusted issuer and use it for a long time
     * independent of that issuer without the risk of an adversary impersonating the Verifier by replaying a captured
     * attestation.
     */
    @SerialName(ClaimNames.RFC7800.CNF)
    override val confirmationClaim: ConfirmationClaim,
) : ClientAttestationClaims.Attestation {
}
