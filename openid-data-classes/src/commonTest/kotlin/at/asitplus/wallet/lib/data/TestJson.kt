package at.asitplus.wallet.lib.data

import kotlinx.serialization.json.Json

internal val vckJsonSerializer = Json {
    prettyPrint = false
    encodeDefaults = false
    classDiscriminator = "type"
    ignoreUnknownKeys = true
}
