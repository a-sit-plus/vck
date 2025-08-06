package at.asitplus.openid

import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic

@Suppress("UNCHECKED_CAST")
private val authorizationDetailsModule = SerializersModule {
    polymorphic(AuthorizationDetails::class) {
        subclass(OpenIdAuthorizationDetails::class, OpenIdAuthorizationDetails.serializer())
    }
    polymorphicDefaultSerializer(
        AuthorizationDetails::class,
        defaultSerializerProvider = {
            when (it) {
                is OpenIdAuthorizationDetails -> OpenIdAuthorizationDetails.serializer() as SerializationStrategy<AuthorizationDetails>
                else -> throw Exception("Serializer for ${it::class} unknown")
            }
        },
    )
    polymorphicDefaultDeserializer(
        AuthorizationDetails::class,
        defaultDeserializerProvider = { OpenIdAuthorizationDetails.serializer() },
    )
}

/**
 * This serialization module allows de-/serialization of open interfaces defined in this module
 */
private val baseOpenIdSerializerModule = SerializersModule {
    include(authorizationDetailsModule)
}

val odcJsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
        serializersModule = baseOpenIdSerializerModule
    }
}
