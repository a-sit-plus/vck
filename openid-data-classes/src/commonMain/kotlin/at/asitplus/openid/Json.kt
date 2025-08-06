package at.asitplus.openid

import at.asitplus.dif.ddcJsonSerializer
import at.asitplus.openid.qes.RequestParametersSerializer
import at.asitplus.openid.qes.SignatureRequestParameters
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.overwriteWith
import kotlinx.serialization.modules.polymorphic

@Suppress("UNCHECKED_CAST")
private val requestParametersModule = SerializersModule {
    polymorphic(RequestParameters::class) {
        subclass(
            SignatureRequestParameters::class,
            SignatureRequestParameters.serializer()
        )
        subclass(
            AuthenticationRequestParameters::class,
            AuthenticationRequestParameters.serializer()
        )
    }
    polymorphicDefaultSerializer(
        RequestParameters::class,
        defaultSerializerProvider = { RequestParametersSerializer },
    )
    polymorphicDefaultDeserializer(
        RequestParameters::class,
        defaultDeserializerProvider = { RequestParametersSerializer }
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

/**
 * This serialization module allows de-/serialization of open interfaces defined in this module
 */
private val baseOpenIdSerializerModule = SerializersModule {
    include(requestParametersModule)
    include(authorizationDetailsModule)
}

val odcJsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
        serializersModule = ddcJsonSerializer.serializersModule.overwriteWith(baseOpenIdSerializerModule)
    }
}
