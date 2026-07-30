package at.asitplus.openid.jwtpayload

import at.asitplus.openid.jwtpayload.claims.ClientAttestationPopClaims
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.JwtClaimNames
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class ClientAttestationPopPayload(
    @SerialName(ClaimNames.RFC7519.AUD)
    override val audience: String,

    @SerialName(ClaimNames.RFC7519.JTI)
    override val jwtId: String,

    @SerialName(ClaimNames.RFC7519.IAT)
    @Serializable(with = InstantLongSerializer::class)
    override val issuedAt: Instant,

    @SerialName(JwtClaimNames.UnregisteredClaims.DraftIetfOauthAttestation.CHALLENGE)
    override val challenge: String? = null,

    @SerialName(ClaimNames.RFC7519.ISS)
    override val issuer: String? = null,

    @SerialName(ClaimNames.RFC7519.SUB)
    override val subject: String? = null,

    @SerialName(ClaimNames.RFC7519.NBF)
    @Serializable(with = InstantLongSerializer::class)
    override val notBefore: Instant? = null,

    @SerialName(ClaimNames.RFC7519.EXP)
    @Serializable(with = InstantLongSerializer::class)
    override val expiration: Instant? = null,

    @SerialName(ClaimNames.RFC9449.NONCE)
    override val nonce: String? = null
) : ClientAttestationPopClaims