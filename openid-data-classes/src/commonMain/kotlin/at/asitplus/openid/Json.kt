package at.asitplus.openid


import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.InputDescriptor
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic

@Suppress("UNCHECKED_CAST")
private val requestParametersModule = SerializersModule {
    polymorphic(RequestParameters::class) {
        subclass(AuthenticationRequestParameters::class, AuthenticationRequestParameters.serializer())
    }
    polymorphicDefaultSerializer(
        RequestParameters::class,
        defaultSerializerProvider = {
            when (it) {
                is AuthenticationRequestParameters -> AuthenticationRequestParameters.serializer() as SerializationStrategy<RequestParameters>
                else -> throw Exception("Serializer for ${it::class} unknown")
            }
        },
    )
    polymorphicDefaultDeserializer(
        RequestParameters::class,
        defaultDeserializerProvider = { AuthenticationRequestParameters.serializer() },
    )
}

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

@Suppress("UNCHECKED_CAST")
private val inputDescriptorModule = SerializersModule {
    polymorphic(InputDescriptor::class) {
        subclass(DifInputDescriptor::class, DifInputDescriptor.serializer())
    }
    polymorphicDefaultSerializer(
        InputDescriptor::class,
        defaultSerializerProvider = {
            when (it) {
                is DifInputDescriptor -> DifInputDescriptor.serializer() as SerializationStrategy<InputDescriptor>
                else -> throw Exception("Serializer for ${it::class} unknown")
            }
        },
    )
    polymorphicDefaultDeserializer(
        InputDescriptor::class,
        defaultDeserializerProvider = { DifInputDescriptor.serializer() },
    )
}

/**
 * This serialization module allows de-/serialization of open interfaces defined in this module
 */
private val baseOpenIdSerializerModule = SerializersModule {
    include(requestParametersModule)
    include(authorizationDetailsModule)
    include(inputDescriptorModule)
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
