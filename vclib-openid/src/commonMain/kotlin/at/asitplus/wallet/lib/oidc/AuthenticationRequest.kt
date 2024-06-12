package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

@Serializable
data class AuthenticationRequest(
    val source: AuthenticationRequestSource,
    val parameters: AuthenticationRequestParameters,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<AuthenticationRequest>(it)
        }.wrap()
    }
}