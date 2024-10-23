package at.asitplus.wallet.lib

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.InputDescriptorInterface
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.RequestParameters
import at.asitplus.wallet.lib.data.JsonSerializerModulesCollector
import at.asitplus.wallet.lib.data.JsonSerializersModuleSet
import kotlinx.serialization.SerializationStrategy
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

    fun initOpenIdModule() {
        with(JsonInputDescriptorSerializerModule) {
            registerSerializersModule(clazz, SerializersModule {
                polymorphic(clazz) {
                    subclass(DifInputDescriptor::class, DifInputDescriptor.serializer())
                }
                polymorphicDefaultSerializer(
                    clazz,
                    defaultSerializerProvider = {
                        when (it) {
                            is DifInputDescriptor -> DifInputDescriptor.serializer() as SerializationStrategy<InputDescriptorInterface>
                            else -> throw Exception("Serializer for ${it::class} unknown")
                        }
                    },
                )
                polymorphicDefaultDeserializer(
                    clazz,
                    defaultDeserializerProvider = { DifInputDescriptor.serializer() },
                )
            })
        }
        with(JsonRequestParametersSerializersModule) {
            registerSerializersModule(clazz, SerializersModule {
                polymorphic(clazz) {
                    subclass(AuthenticationRequestParameters::class, AuthenticationRequestParameters.serializer())
                }
                polymorphicDefaultSerializer(
                    clazz,
                    defaultSerializerProvider = {
                        when (it) {
                            is AuthenticationRequestParameters -> AuthenticationRequestParameters.serializer() as SerializationStrategy<RequestParameters>
                            else -> throw Exception("Serializer for ${it::class} unknown")
                        }
                    },
                )
                polymorphicDefaultDeserializer(
                    clazz,
                    defaultDeserializerProvider = { AuthenticationRequestParameters.serializer() },
                )
            })
        }
        with(JsonAuthorizationDetailsSerializersModule) {
            registerSerializersModule(clazz, SerializersModule {
                polymorphic(clazz) {
                    subclass(OpenIdAuthorizationDetails::class, OpenIdAuthorizationDetails.serializer())
                }
                polymorphicDefaultSerializer(
                    clazz,
                    defaultSerializerProvider = {
                        when (it) {
                            is OpenIdAuthorizationDetails -> OpenIdAuthorizationDetails.serializer() as SerializationStrategy<AuthorizationDetails>
                            else -> throw Exception("Serializer for ${it::class} unknown")
                        }
                    },
                )
                polymorphicDefaultDeserializer(
                    clazz,
                    defaultDeserializerProvider = { OpenIdAuthorizationDetails.serializer() },
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