package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames.RFC7519
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames.RFC9449
import at.asitplus.signum.indispensable.josef.JwtPayload
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Deprecated("Renamed", replaceWith = ReplaceWith("VerifiablePresentationPayload"))
typealias VerifiablePresentationJws = VerifiablePresentationPayload


/**
 * JWS representation of a [VerifiablePresentation].
 */
@Serializable
data class VerifiablePresentationPayload(
    @SerialName("vp")
    val vp: VerifiablePresentation,
    @SerialName(RFC9449.NONCE)
    val challenge: String,
    @SerialName(RFC7519.ISS)
    override val issuer: String,
    @SerialName(RFC7519.AUD)
    override val audience: String,
    @SerialName(RFC7519.JTI)
    override val jwtId: String,
) : JwtPayload {
    override val subject: String? = null
    override val notBefore: Instant? = null
    override val issuedAt: Instant? = null
    override val expiration: Instant? = null
}