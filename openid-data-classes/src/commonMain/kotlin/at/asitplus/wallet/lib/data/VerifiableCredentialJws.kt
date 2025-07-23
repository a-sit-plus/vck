package at.asitplus.wallet.lib.data

import kotlin.time.Instant
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * JWS representation of a [VerifiableCredential].
 */
@Serializable
data class VerifiableCredentialJws(
    @SerialName("vc")
    val vc: VerifiableCredential,
    @SerialName("sub")
    val subject: String,
    @SerialName("nbf")
    @Serializable(with = InstantLongSerializer::class)
    val notBefore: Instant,
    @SerialName("iss")
    val issuer: String,
    @SerialName("exp")
    @Serializable(with = NullableInstantLongSerializer::class)
    val expiration: Instant?,
    @SerialName("jti")
    val jwtId: String,
)