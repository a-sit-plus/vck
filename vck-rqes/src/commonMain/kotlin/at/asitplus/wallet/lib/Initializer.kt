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
import at.asitplus.wallet.lib.data.JsonSerializerModulesCollector
import at.asitplus.wallet.lib.data.JsonSerializersModuleSet
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic

object Initializer {

    val JsonInputDescriptorSerializerModule: JsonSerializerModulesCollector<InputDescriptorInterface> =
        (JsonSerializersModuleSet.firstOrNull { it.clazz == InputDescriptorInterface::class } as JsonSerializerModulesCollector<InputDescriptorInterface>?)
            ?: JsonSerializerModulesCollector(InputDescriptorInterface::class)

    val JsonRequestParametersSerializersModule: JsonSerializerModulesCollector<RequestParameters> =
        (JsonSerializersModuleSet.firstOrNull { it.clazz == RequestParameters::class } as JsonSerializerModulesCollector<RequestParameters>?)
            ?: JsonSerializerModulesCollector(RequestParameters::class)

    val JsonAuthorizationDetailsSerializersModule: JsonSerializerModulesCollector<AuthorizationDetails> =
        (JsonSerializersModuleSet.firstOrNull { it.clazz == AuthorizationDetails::class } as JsonSerializerModulesCollector<AuthorizationDetails>?)
            ?: JsonSerializerModulesCollector(AuthorizationDetails::class)

    /**
     * A reference to this class is enough to trigger the init block
     */
    init {
        initRqesModule()
    }

    fun initRqesModule() {
        with(JsonInputDescriptorSerializerModule) {
            registerSerializersModule(clazz, SerializersModule {
                polymorphic(clazz) {
                    subclass(DifInputDescriptor::class, DifInputDescriptor.serializer())
                    subclass(QesInputDescriptor::class, QesInputDescriptor.serializer())
                }
            })
        }
        with(JsonRequestParametersSerializersModule) {
            registerSerializersModule(clazz, SerializersModule {
                polymorphic(clazz) {
                    subclass(SignatureRequestParameters::class, SignatureRequestParameters.serializer())
                    subclass(AuthenticationRequestParameters::class, AuthenticationRequestParameters.serializer())
                    subclass(CscAuthenticationRequestParameters::class, CscAuthenticationRequestParameters.serializer())
                }
            })
        }
        with(JsonAuthorizationDetailsSerializersModule) {
            registerSerializersModule(clazz, SerializersModule {
                polymorphic(clazz) {
                    subclass(CscAuthorizationDetails::class, CscAuthorizationDetails.serializer())
                    subclass(OpenIdAuthorizationDetails::class, OpenIdAuthorizationDetails.serializer())
                }
            })
        }
        JsonSerializersModuleSet.addAll(listOf(JsonInputDescriptorSerializerModule, JsonRequestParametersSerializersModule, JsonAuthorizationDetailsSerializersModule))
    }
}