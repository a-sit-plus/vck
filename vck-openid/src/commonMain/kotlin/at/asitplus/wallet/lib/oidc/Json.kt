package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.vckJsonSerializer
import kotlinx.serialization.json.Json

@Deprecated("Use vckJsonSerializer",
    ReplaceWith("vckJsonSerializer", "at.asitplus.wallet.lib.data"))
val jsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
        serializersModule = vckJsonSerializer.serializersModule
    }
}
