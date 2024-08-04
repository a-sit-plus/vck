package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.JsonValueEncoder
import at.asitplus.wallet.lib.data.JsonCredentialSerializer.serializersModules
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

internal object JsonCredentialSerializer {

    val serializersModules = mutableMapOf<ConstantIndex.CredentialScheme, SerializersModule>()
    val jsonElementEncoder = mutableSetOf<JsonValueEncoder>()

    fun registerSerializersModule(scheme: ConstantIndex.CredentialScheme, module: SerializersModule) {
        serializersModules[scheme] = module
    }

    fun register(function: JsonValueEncoder) {
        jsonElementEncoder += function
    }

    fun encode(value: Any): JsonElement? =
        jsonElementEncoder.firstNotNullOfOrNull { it.invoke(value) }

}

val vckJsonSerializer by lazy {
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
                include(it.value)
            }
        }
    }
}

