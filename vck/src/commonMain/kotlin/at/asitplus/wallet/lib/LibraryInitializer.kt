@file:Suppress("unused")

package at.asitplus.wallet.lib

import at.asitplus.wallet.lib.data.AriesGoalCodeParser
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import at.asitplus.wallet.lib.data.JsonCredentialSerializer
import at.asitplus.wallet.lib.iso.CborCredentialSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.CompositeEncoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.modules.SerializersModule

/**
 * Called by other libraries to extend credentials by subclassing [at.asitplus.wallet.lib.data.CredentialSubject].
 */
object LibraryInitializer {

    @Deprecated(message = "Please use methods that do not use this data class")
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
    @Deprecated(
        message = "Please use methods not using the data class",
        replaceWith = ReplaceWith("registerExtensionLibrary(credentialScheme, serializersModule)")
    )
    fun registerExtensionLibrary(@Suppress("DEPRECATION") data: ExtensionLibraryInfo) {
        registerExtensionLibrary(data.credentialScheme, data.serializersModule)
    }

    /**
     * Register [credentialScheme] to be used with this library, e.g. in OpenID protocol implementations.
     *
     * Specify [serializersModule] if the credential scheme supports [ConstantIndex.CredentialRepresentation.PLAIN_JWT],
     * i.e. it implements a subclass of [at.asitplus.wallet.lib.data.CredentialSubject] that needs to be de/serialized.
     */
    fun registerExtensionLibrary(
        credentialScheme: ConstantIndex.CredentialScheme,
        serializersModule: SerializersModule? = null
    ) {
        AttributeIndex.registerAttributeType(credentialScheme)
        if (credentialScheme.supportsVcJwt)
            AriesGoalCodeParser.registerGoalCode(credentialScheme)
        serializersModule?.let { JsonCredentialSerializer.registerSerializersModule(credentialScheme, it) }
    }

    /**
     * Register [credentialScheme] to be used with this library, e.g. in OpenID protocol implementations.
     * Used for credentials supporting [at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC],
     * which need to specify several functions to allow encoding any values
     * in [at.asitplus.wallet.lib.iso.IssuerSignedItem]. See the function typealiases for implementation notes.
     *
     * @param serializerLookup used to build the serializer descriptor for [at.asitplus.wallet.lib.iso.IssuerSignedItem]
     * @param itemValueEncoder used to actually serialize the element value in [at.asitplus.wallet.lib.iso.IssuerSignedItemSerializer]
     * @param jsonValueEncoder used to describe the credential in input descriptors used in verifiable presentations,
     *                         e.g. when used in SIOPv2
     * @param itemValueDecoderMap used to actually deserialize `Any` object in [at.asitplus.wallet.lib.iso.IssuerSignedItemSerializer],
     * with `elementIdentifier` as the key
     */
    fun registerExtensionLibrary(
        credentialScheme: ConstantIndex.CredentialScheme,
        serializersModule: SerializersModule? = null,
        serializerLookup: SerializerLookup,
        itemValueEncoder: ItemValueEncoder,
        jsonValueEncoder: JsonValueEncoder,
        itemValueDecoderMap: ElementIdentifierToItemValueSerializerMap = emptyMap(),
    ) {
        registerExtensionLibrary(credentialScheme, serializersModule)
        CborCredentialSerializer.register(serializerLookup)
        CborCredentialSerializer.register(itemValueEncoder)
        JsonCredentialSerializer.register(jsonValueEncoder)
        credentialScheme.isoNamespace?.let { CborCredentialSerializer.register(itemValueDecoderMap, it) }
    }

}

/**
 * Implementation may be
 * ```
 * if (value is Array<*> && value.isNotEmpty() && value.all { it is DrivingPrivilege }) {
 *     true.also {
 *         compositeEncoder.encodeSerializableElement(
 *             descriptor,
 *             index,
 *             ArraySerializer<DrivingPrivilege, DrivingPrivilege>(DrivingPrivilege.serializer()),
 *             value as Array<DrivingPrivilege>
 *         )
 *     }
 * } else {
 *     false
 * }
 * ```
 */
typealias ItemValueEncoder
        = (descriptor: SerialDescriptor, index: Int, compositeEncoder: CompositeEncoder, value: Any) -> Boolean

/**
 * Implementation may be
 * ```
 * compositeDecoder.decodeSerializableElement(
 *     descriptor,
 *     index,
 *     ArraySerializer(DrivingPrivilege.serializer())
 * )
 * ```
 */
typealias ItemValueDecoder
        = (descriptor: SerialDescriptor, index: Int, compositeDecoder: CompositeDecoder) -> Any

/**
 * Implementation may be
 * ```
 * if (it is Array<*>) ArraySerializer(DrivingPrivilege.serializer()) else null
 * ```
 */
typealias SerializerLookup
        = (element: Any) -> KSerializer<*>?

/**
 * Implementation may be
 * ```
 * if (it is DrivingPrivilege) jsonSerializer.encodeToJsonElement(it) else null
 * ```
 */
typealias JsonValueEncoder
        = (value: Any) -> JsonElement?

/**
 * Maps from `IssuerSignedItem.elementIdentifier` to its corresponding [KSerializer]
 */
typealias ElementIdentifierToItemValueSerializerMap
        = Map<String, KSerializer<*>>