package at.asitplus.rqes

import CscAuthorizationDetails
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.InputDescriptorInterface
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CscAuthenticationRequestParameters
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.RequestParameters
import at.asitplus.rqes.serializers.AuthorizationDetailsSerializer
import at.asitplus.rqes.serializers.InputDescriptorSerializer
import at.asitplus.rqes.serializers.RequestParametersSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.overwriteWith
import kotlinx.serialization.modules.polymorphic

private val inputDescriptorModule = SerializersModule {
    polymorphic(InputDescriptorInterface::class) {
        subclass(DifInputDescriptor::class, DifInputDescriptor.serializer())
        subclass(QesInputDescriptor::class, QesInputDescriptor.serializer())
    }
    polymorphicDefaultSerializer(
        InputDescriptorInterface::class,
        defaultSerializerProvider = { InputDescriptorSerializer },
    )
    polymorphicDefaultDeserializer(
        InputDescriptorInterface::class,
        defaultDeserializerProvider = { InputDescriptorSerializer }
    )
}

private val requestParametersModule = SerializersModule {
    polymorphic(RequestParameters::class) {
        subclass(SignatureRequestParameters::class, SignatureRequestParameters.serializer())
        subclass(AuthenticationRequestParameters::class, AuthenticationRequestParameters.serializer())
        subclass(CscAuthenticationRequestParameters::class, CscAuthenticationRequestParameters.serializer())
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

private val authorizationDetailsModule = SerializersModule {
    polymorphic(AuthorizationDetails::class) {
        subclass(CscAuthorizationDetails::class, CscAuthorizationDetails.serializer())
        subclass(OpenIdAuthorizationDetails::class, OpenIdAuthorizationDetails.serializer())
    }
    polymorphicDefaultSerializer(
        AuthorizationDetails::class,
        defaultSerializerProvider = { AuthorizationDetailsSerializer },
    )
    polymorphicDefaultDeserializer(
        AuthorizationDetails::class,
        defaultDeserializerProvider = { AuthorizationDetailsSerializer }
    )
}

/**
 * This module fully overrides the one specified in `at.asitplus.openid.Json.kt`
 * It allows de-/serialization of open interfaces defined in this module as well as the OpenId module
 */
private val extendedOpenIdSerializerModule = SerializersModule {
    include(inputDescriptorModule)
    include(requestParametersModule)
    include(authorizationDetailsModule)
}


val rdcJsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
        serializersModule = extendedOpenIdSerializerModule
    }
}
