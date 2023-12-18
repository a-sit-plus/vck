package at.asitplus.wallet.lib.data

import io.github.aakira.napier.Napier
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Key Binding JWT for SD-JWT
 */
@Serializable
data class KeyBindingJws(
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant? = null,
    @SerialName("aud")
    val audience: String,
    @SerialName("nonce")
    val challenge: String,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<KeyBindingJws>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}