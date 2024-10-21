package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.JsonValueEncoder
import io.github.aakira.napier.Napier
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass
import kotlin.reflect.KClass

class JsonSerializerModulesCollector<T : Any>(
    val clazz: KClass<T>,
) {
    init {
        JsonSerializersModuleSet.add(this)
    }

    val serializersModules = mutableMapOf<KClass<out T>, SerializersModule>()
    private val jsonElementEncoder = mutableSetOf<JsonValueEncoder>()

    fun registerSerializersModule(target: KClass<out T>, module: SerializersModule) {
        serializersModules[target] = module
    }

    fun register(function: JsonValueEncoder) {
        jsonElementEncoder += function
    }

    fun encode(value: Any): JsonElement? =
        jsonElementEncoder.firstNotNullOfOrNull { it.invoke(value) }

}

internal val JsonCredentialSerializer = JsonSerializerModulesCollector(ConstantIndex.CredentialScheme::class)

/**
 * Used to find instances of [JsonSerializerModulesCollector] at runtime
 */
internal val JsonSerializersModuleSet = mutableSetOf<JsonSerializerModulesCollector<*>>()

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
            JsonSerializersModuleSet.forEach {
                it.serializersModules.forEach {
                    include(it.value)
                }
            }.also { Napier.d("Registered SerializersModules: ${JsonSerializersModuleSet.map { it.clazz }}") }
        }
    }
}

