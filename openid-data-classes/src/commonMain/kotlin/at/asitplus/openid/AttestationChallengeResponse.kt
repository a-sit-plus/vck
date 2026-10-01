package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Challenges for
 * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html#name-challenges)
 */
@Serializable
data class AttestationChallengeResponse(
    /**
     * REQUIRED if the Authorization Server or Resource Server supports Client Attestations and server-provided
     * challenges as described in
     * [this document](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html#name-challenges)
     * .
     * String containing a Challenge to be used in the Client Attestation PoP JWT or DPoP Proof as defined in Section 5.
     * The intention of this element not being required in other circumstances is to preserve the ability for the
     * challenge endpoint to be used in other applications unrelated to client attestations.
     */
    @SerialName("attestation_challenge")
    val attestationChallenge: String,
)