package at.asitplus.openid.jwtpayload

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.JwtClaimNames
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant


/**
 * Defined in [draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-10)
 */
@Serializable
data class ClientAttestationPopPayload(
    @SerialName(ClaimNames.RFC7519.ISS)
    override val issuer: String? = null,
    @SerialName(ClaimNames.RFC7519.SUB)
    override val subject: String? = null,
    /**
     * aud: REQUIRED.  The aud (audience) claim MUST specify a value that
     *       identifies the intended audience of the JWT.  When the JWT is
     *       presented to an Authorization Server, the [RFC8414] issuer
     *       identifier URL of the Authorization Server MUST be used.  When the
     *       JWT is presented to a Resource Server, the [RFC9728] resource
     *       identifier URL of the Resource Server MUST be used.  A Client
     *       Attestation PoP JWT is intended for a single audience, Clients
     *       MUST generate JWTs for each target.
     */
    @SerialName(ClaimNames.RFC7519.AUD)
    override val audience: String,
    @SerialName(ClaimNames.RFC7519.NBF)
    @Serializable(with = InstantLongSerializer::class)
    override val notBefore: Instant? = null,
    /**
     * iat: REQUIRED.  The iat (issued at) claim MUST specify the time at
     *       which the Client Attestation PoP was issued.  Note that the
     *       Authorization Server or Resource Server may reject JWTs with an
     *       "iat" claim value that is unreasonably far in the past.
     */
    @SerialName(ClaimNames.RFC7519.IAT)
    @Serializable(with = InstantLongSerializer::class)
    override val issuedAt: Instant,
    @SerialName(ClaimNames.RFC7519.EXP)
    @Serializable(with = InstantLongSerializer::class)
    override val expiration: Instant? = null,
    /**
     * jti: REQUIRED.  The jti (JWT identifier) claim MUST specify a
     *       unique identifier for the Client Attestation PoP.  The
     *       Authorization Server or Resource Server can utilize the jti value
     *       for replay attack detection, see Section 11.1.
     */
    @SerialName(ClaimNames.RFC7519.JTI)
    override val jwtId: String,
    /**
     * challenge: OPTIONAL.  The challenge (challenge) claim MUST specify
     *       a String value that is provided by the Authorization Server or
     *       Resource Server for the client to include in the Client
     *       Attestation PoP JWT.
     */
    @SerialName(JwtClaimNames.UnregisteredClaims.DraftIetfOauthAttestation.CHALLENGE)
    override val challenge: String? = null
) : ClientAttestationClaims.ProofOfPossession {
}