package at.asitplus.wallet.lib.data

import at.asitplus.catching
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

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

    fun serialize() = vckJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = catching {
            vckJsonSerializer.decodeFromString<VerifiablePresentationJws>(it)
        }
    }

}