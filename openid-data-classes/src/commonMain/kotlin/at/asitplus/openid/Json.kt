package at.asitplus.openid

import kotlinx.serialization.json.Json

// TODO: Review if removable
val odcJsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
    }
}
