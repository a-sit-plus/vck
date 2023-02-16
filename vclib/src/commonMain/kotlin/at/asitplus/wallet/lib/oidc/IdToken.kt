package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.InstantLongSerializer
import at.asitplus.wallet.lib.data.jsonSerializer
import at.asitplus.wallet.lib.jws.JsonWebKey
import io.github.aakira.napier.Napier
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString

/**
 * OpenID Connect ID Token, usually signed as JWS in `id_token` in a URL
 */
@Serializable
data class IdToken(
    @SerialName("iss")
    val issuer: String,
    @SerialName("aud")
    val audience: String,
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant,
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant,
    @SerialName("sub")
    val subject: String,
    @SerialName("nonce")
    val nonce: String,
    @SerialName("sub_jwk")
    val subjectJwk: JsonWebKey? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<IdToken>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}