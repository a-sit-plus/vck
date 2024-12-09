package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtStatusPayloadClaimSpecification
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

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
    @SerialName(JwtStatusPayloadClaimSpecification.NAME)
    val status: Status,
) {
    fun serialize() = vckJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            vckJsonSerializer.decodeFromString<VerifiableCredentialJws>(it)
        }.wrap()
    }

}

