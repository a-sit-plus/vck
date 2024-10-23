package at.asitplus.wallet.lib

import CscAuthorizationDetails
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.InputDescriptorInterface
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CscAuthenticationRequestParameters
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.RequestParameters
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.rqes.SignatureRequestParameters
import at.asitplus.rqes.serializers.AuthorizationDetailsSerializer
import at.asitplus.rqes.serializers.InputDescriptorSerializer
import at.asitplus.rqes.serializers.RequestParametersSerializer
import at.asitplus.wallet.lib.data.JsonSerializerModulesCollector
import at.asitplus.wallet.lib.data.JsonSerializersModuleSet
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic


object Initializer {
    val JsonInputDescriptorSerializerModule: JsonSerializerModulesCollector<InputDescriptorInterface> =
        JsonSerializerModulesCollector(InputDescriptorInterface::class)

    val JsonRequestParametersSerializersModule: JsonSerializerModulesCollector<RequestParameters> =
        JsonSerializerModulesCollector(RequestParameters::class)

    val JsonAuthorizationDetailsSerializersModule: JsonSerializerModulesCollector<AuthorizationDetails> =
        JsonSerializerModulesCollector(AuthorizationDetails::class)


    /**
     * Override serializer modules if previously defined
     */
    init {
        JsonSerializersModuleSet.removeAll { it.clazz == InputDescriptorInterface::class }
        JsonSerializersModuleSet.removeAll { it.clazz == RequestParameters::class }
        JsonSerializersModuleSet.removeAll { it.clazz == AuthorizationDetails::class }
    }

    fun initRqesModule() {
        with(JsonInputDescriptorSerializerModule) {
            registerSerializersModule(clazz, SerializersModule {
                polymorphic(clazz) {
                    subclass(DifInputDescriptor::class, DifInputDescriptor.serializer())
                    subclass(QesInputDescriptor::class, QesInputDescriptor.serializer())
                }
                polymorphicDefaultSerializer(
                    clazz,
                    defaultSerializerProvider = { InputDescriptorSerializer },
                )
                polymorphicDefaultDeserializer(
                    clazz,
                    defaultDeserializerProvider = { InputDescriptorSerializer }
                )
            })
        }
        with(JsonRequestParametersSerializersModule) {
            registerSerializersModule(clazz, SerializersModule {
                polymorphic(clazz) {
                    subclass(SignatureRequestParameters::class, SignatureRequestParameters.serializer())
                    subclass(AuthenticationRequestParameters::class, AuthenticationRequestParameters.serializer())
                    subclass(CscAuthenticationRequestParameters::class, CscAuthenticationRequestParameters.serializer())
                }
                polymorphicDefaultSerializer(
                    clazz,
                    defaultSerializerProvider = { RequestParametersSerializer },
                )
                polymorphicDefaultDeserializer(
                    clazz,
                    defaultDeserializerProvider = { RequestParametersSerializer }
                )
            })
        }
        with(JsonAuthorizationDetailsSerializersModule) {
            registerSerializersModule(clazz, SerializersModule {
                polymorphic(clazz) {
                    subclass(CscAuthorizationDetails::class, CscAuthorizationDetails.serializer())
                    subclass(OpenIdAuthorizationDetails::class, OpenIdAuthorizationDetails.serializer())
                }
                polymorphicDefaultSerializer(
                    clazz,
                    defaultSerializerProvider = { AuthorizationDetailsSerializer },
                )
                polymorphicDefaultDeserializer(
                    clazz,
                    defaultDeserializerProvider = { AuthorizationDetailsSerializer }
                )
            })
        }
        JsonSerializersModuleSet.addAll(
            listOf(
                JsonInputDescriptorSerializerModule,
                JsonRequestParametersSerializersModule,
                JsonAuthorizationDetailsSerializersModule
            )
        )
    }
}