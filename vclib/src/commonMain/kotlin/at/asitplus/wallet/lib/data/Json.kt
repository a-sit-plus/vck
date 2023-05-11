package at.asitplus.wallet.lib.data

import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

private val serializersModules = mutableListOf<SerializersModule>()

internal fun registerSerializersModule(module: SerializersModule) {
    serializersModules += module
}

val jsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
        serializersModule = SerializersModule {
            polymorphic(CredentialSubject::class) {
                subclass(AtomicAttribute2023::class)
                subclass(RevocationListSubject::class)
            }
            serializersModules.forEach {
                include(it)
            }
        }
    }
}
