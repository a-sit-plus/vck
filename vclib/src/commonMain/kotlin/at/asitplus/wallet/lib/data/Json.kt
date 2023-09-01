package at.asitplus.wallet.lib.data

import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.base64.Base64ConfigBuilder
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

private val serializersModules = mutableMapOf<ConstantIndex.CredentialScheme, SerializersModule>()

internal fun registerSerializersModule(scheme: ConstantIndex.CredentialScheme, module: SerializersModule) {
    serializersModules[scheme] = module
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
                include(it.value)
            }
        }
    }
}

val Base64Url = Base64(config = Base64ConfigBuilder().apply {
    lineBreakInterval = 0
    encodeToUrlSafe = true
    isLenient = true
    padEncoded = false
}.build())