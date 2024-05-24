@file:Suppress("unused")

package at.asitplus.wallet.lib

import at.asitplus.wallet.lib.data.AriesGoalCodeParser
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.Json
import at.asitplus.wallet.lib.iso.Cbor
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeEncoder
import kotlinx.serialization.modules.SerializersModule

/**
 * Called by other libraries to extend credentials by subclassing [at.asitplus.wallet.lib.data.CredentialSubject].
 */
object LibraryInitializer {

    data class ExtensionLibraryInfo(
        /**
         * Implementation of [at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme].
         */
        val credentialScheme: ConstantIndex.CredentialScheme,
        /**
         * Definition of a polymorphic serializers module in this form:
         * ```
         * kotlinx.serialization.modules.SerializersModule {
         *     kotlinx.serialization.modules.polymorphic(CredentialSubject::class) {
         *         kotlinx.serialization.modules.subclass(YourCredential::class)
         *     }
         * }
         * ```
         */
        val serializersModule: SerializersModule,
    )

    /**
     * Register the extension library with information from [data].
     */
    fun registerExtensionLibrary(data: ExtensionLibraryInfo) {
        AriesGoalCodeParser.registerGoalCode(data.credentialScheme)
        AttributeIndex.registerAttributeType(data.credentialScheme)
        Json.registerSerializersModule(data.credentialScheme, data.serializersModule)
    }

    fun registerExtensionLibrary(
        data: ExtensionLibraryInfo,
        itemValueLookup: DescriptorLookup,
        itemValueEncoder: ItemValueEncoder
    ) {
        registerExtensionLibrary(data)
        itemValueLookup.let { Cbor.register(it) }
        itemValueEncoder.let { Cbor.register(it) }
    }

}
typealias ItemValueEncoder
        = (descriptor: SerialDescriptor, index: Int, compositeEncoder: CompositeEncoder, value: Any) -> Boolean

typealias DescriptorLookup
        = (element: Any) -> KSerializer<*>?