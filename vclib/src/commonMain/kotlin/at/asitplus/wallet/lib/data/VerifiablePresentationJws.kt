package at.asitplus.wallet.lib.data

import io.github.aakira.napier.Napier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * JWS representation of a [VerifiablePresentation].
 */
@Serializable
data class VerifiablePresentationJws(
    @SerialName("vp")
    val vp: VerifiablePresentation,
    @SerialName("nonce")
    val challenge: String,
    @SerialName("iss")
    val issuer: String,
    @SerialName("aud")
    val audience: String,
    @SerialName("jti")
    val jwtId: String
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<VerifiablePresentationJws>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}