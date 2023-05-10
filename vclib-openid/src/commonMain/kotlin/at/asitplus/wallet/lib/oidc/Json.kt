package at.asitplus.wallet.lib.oidc

import kotlinx.serialization.json.Json

val jsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
    }
}
