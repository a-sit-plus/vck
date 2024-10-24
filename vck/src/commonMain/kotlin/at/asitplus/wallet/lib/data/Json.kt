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

var serializerModuleCollection = SerializersModule {}

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
            include(serializerModuleCollection)
        }
    }
}


//
////TODO LOOK AT NOTES!!
//asdfasdfsfs
//
//class JsonSerializerModulesCollector<T : Any>(
//    val clazz: KClass<T>,
//) {
//    val serializersModules = mutableMapOf<KClass<out T>, SerializersModule>()
//    private val jsonElementEncoder = mutableSetOf<JsonValueEncoder>()
//
//    fun registerSerializersModule(target: KClass<out T>, module: SerializersModule) {
//        serializersModules[target] = module
//    }
//
//    fun register(function: JsonValueEncoder) {
//        jsonElementEncoder += function
//    }
//
//    fun encode(value: Any): JsonElement? =
//        jsonElementEncoder.firstNotNullOfOrNull { it.invoke(value) }
//
//}
//
//internal val JsonCredentialSerializer = JsonSerializerModulesCollector(ConstantIndex.CredentialScheme::class)
//
///**
// * Used to find instances of [JsonSerializerModulesCollector] at runtime
// */
//val JsonSerializersModuleSet = mutableSetOf<JsonSerializerModulesCollector<*>>(JsonCredentialSerializer)
//
//
//val vckJsonSerializer by lazy {
//    Json {
//        prettyPrint = false
//        encodeDefaults = false
//        classDiscriminator = "type"
//        ignoreUnknownKeys = true
//        serializersModule = SerializersModule {
//            polymorphic(CredentialSubject::class) {
//                subclass(AtomicAttribute2023::class)
//                subclass(RevocationListSubject::class)
//            }
//            JsonSerializersModuleSet.forEach {
//                it.serializersModules.forEach {
//                    include(it.value)
//                }
//            }.also { Napier.d("Registered SerializersModules: ${JsonSerializersModuleSet.map { it.clazz }}") }
//        }
//    }
//}

