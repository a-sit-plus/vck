package at.asitplus.rqes

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.InputDescriptor
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TransactionData
import at.asitplus.openid.odcJsonSerializer
import at.asitplus.rqes.collection_entries.QCertCreationAcceptance
import at.asitplus.rqes.collection_entries.QesAuthorization
import at.asitplus.rqes.serializers.InputDescriptorSerializer
import at.asitplus.rqes.serializers.RequestParametersSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual
import kotlinx.serialization.modules.overwriteWith
import kotlinx.serialization.modules.polymorphic

private val inputDescriptorModule = SerializersModule {
    polymorphic(InputDescriptor::class) {
        subclass(DifInputDescriptor::class, DifInputDescriptor.serializer())
        subclass(QesInputDescriptor::class, QesInputDescriptor.serializer())
    }
    polymorphicDefaultSerializer(
        InputDescriptor::class,
        defaultSerializerProvider = { InputDescriptorSerializer },
    )
    polymorphicDefaultDeserializer(
        InputDescriptor::class,
        defaultDeserializerProvider = { InputDescriptorSerializer }
    )
    contextual(InputDescriptorSerializer)
}

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

private val authorizationDetailsModule = SerializersModule {
    polymorphic(AuthorizationDetails::class) {
        subclass(CscAuthorizationDetails::class, CscAuthorizationDetails.serializer())
        subclass(OpenIdAuthorizationDetails::class, OpenIdAuthorizationDetails.serializer())
    }
}

private val transactionDataModule = SerializersModule {
    polymorphic(TransactionData::class) {
        subclass(QesAuthorization::class, QesAuthorization.serializer())
        subclass(QCertCreationAcceptance::class, QCertCreationAcceptance.serializer())
    }
}

/**
 * This module fully overrides the one specified in `at.asitplus.openid.Json.kt`
 * It allows de-/serialization of open interfaces defined in this module as well as the OpenId module
 */
private val extendedOpenIdSerializerModule = SerializersModule {
    include(inputDescriptorModule)
    include(requestParametersModule)
    include(authorizationDetailsModule)
    include(transactionDataModule)
}


val rdcJsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
        serializersModule = odcJsonSerializer.serializersModule.overwriteWith(extendedOpenIdSerializerModule)
    }
}
