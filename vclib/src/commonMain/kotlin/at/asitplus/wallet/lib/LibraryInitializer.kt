@file:Suppress("unused")

package at.asitplus.wallet.lib

import at.asitplus.wallet.lib.data.AriesGoalCodeParser
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.registerSerializersModule
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
        registerSerializersModule(data.credentialScheme, data.serializersModule)
    }

}