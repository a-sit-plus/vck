package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.json.Json

val jsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        ignoreUnknownKeys = true
        isLenient = true
    }
}