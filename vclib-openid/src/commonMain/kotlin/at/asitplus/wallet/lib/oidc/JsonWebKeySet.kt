package at.asitplus.wallet.lib.oidc

import at.asitplus.crypto.datatypes.jws.JsonWebKey
import io.github.aakira.napier.Napier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

@Serializable
data class JsonWebKeySet(
    @SerialName("keys")
    val keys: Collection<JsonWebKey>,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<JsonWebKeySet>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}