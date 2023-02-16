package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.jsonSerializer
import io.github.aakira.napier.Napier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString

@Serializable
data class AuthnRequestClaims(
    @SerialName("id_token")
    val idToken: AuthnRequestClaimsIdToken? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<AuthnRequestClaims>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}

@Serializable
data class AuthnRequestClaimsIdToken(
    @SerialName("acr")
    val acr: String,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<AuthnRequestClaimsIdToken>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}

