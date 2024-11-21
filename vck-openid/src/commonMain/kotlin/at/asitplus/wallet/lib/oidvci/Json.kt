package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.data.vckJsonSerializer
import kotlinx.serialization.json.Json

val jsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        ignoreUnknownKeys = true
        isLenient = true
        serializersModule = vckJsonSerializer.serializersModule
    }
}