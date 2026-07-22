@file:Suppress("unused")

package at.asitplus.wallet.lib

import at.asitplus.iso.CborCredentialSerializer
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialMetadataRegistry
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.JsonCredentialSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonElement

/**
 * Called by other libraries to register credential schemes with this library.
 */
object LibraryInitializer {

    fun registerCredentialMetadataRegistry(
        credentialMetadataRegistry: CredentialMetadataRegistry
    ) {
        AttributeIndex.registerCredentialMetadataRegistry(credentialMetadataRegistry)
    }

    /**
     * Register [credentialScheme] to be used with this library, e.g. in OpenID protocol implementations.
     */
    fun registerExtensionLibrary(
        credentialScheme: CredentialScheme,
    ) {
        AttributeIndex.registerAttributeType(credentialScheme)
    }

    @Suppress("DEPRECATION")
    @Deprecated("Use the other method with CredentialScheme not from ConstantIndex")
    fun registerExtensionLibrary(
        credentialScheme: ConstantIndex.CredentialScheme,
    ) {
        AttributeIndex.registerAttributeType(credentialScheme)
    }

    /**
     * Register encoders for certain types used in ISO mDoc credential schemes,
     * to help encoding "any" values in [at.asitplus.iso.IssuerSignedItem].
     * See the function typealiases in [JsonValueEncoder] and [ElementIdentifierToItemValueSerializerMap]
     * for implementation notes.
     * Example for [jsonValueEncoder]:
     * ```
     * when (it) {
     *     is DrivingPrivilege -> joseCompliantSerializer.encodeToJsonElement(it)
     *     is LocalDate -> joseCompliantSerializer.encodeToJsonElement(it)
     *     is UInt -> joseCompliantSerializer.encodeToJsonElement(it)
     *     else -> null
     * }
     * ```
     *
     * Example for [itemValueSerializerMap]:
     * ```
     * mapOf(
     *     "org.iso.18013.5.1" to mapOf(
     *         MobileDrivingLicenceDataElements.BIRTH_DATE to LocalDate.serializer(),
     *         MobileDrivingLicenceDataElements.PORTRAIT to ByteArraySerializer(),
     *     )
     * )
     * ```
     *
     * @param jsonValueEncoder used to describe the credential in input descriptors (Presentation Exchange)
     * @param itemValueSerializerMap used to actually serialize and deserialize `Any` object in
     * [at.asitplus.iso.IssuerSignedItemSerializer], with `elementIdentifier` and `namespace` as the keys
     */
    fun registerCredentialSerializers(
        jsonValueEncoder: JsonValueEncoder,
        itemValueSerializerMap: IsoNamespaceToElementIdentifierToItemValueSerializerMap = mapOf(),
    ) {
        JsonCredentialSerializer.register(jsonValueEncoder)
        itemValueSerializerMap.forEach {
            CborCredentialSerializer.register(it.value, it.key)
        }
    }

    @Suppress("DEPRECATION")
    @Deprecated("Use registerCredentialMetadataRegistry for schemes and registerCredentialSerializers for serializers")
    fun registerExtensionLibrary(
        credentialScheme: ConstantIndex.CredentialScheme,
        jsonValueEncoder: JsonValueEncoder,
        itemValueSerializerMap: ElementIdentifierToItemValueSerializerMap = emptyMap(),
    ) {
        registerExtensionLibrary(credentialScheme as CredentialScheme)
        JsonCredentialSerializer.register(jsonValueEncoder)
        credentialScheme.isoNamespace?.let { CborCredentialSerializer.register(itemValueSerializerMap, it) }
    }
}

/**
 * Used to encode any value into a [JsonElement], implementation may be
 * ```
 * when (it) {
 *     is DrivingPrivilege -> joseCompliantSerializer.encodeToJsonElement(it)
 *     else -> null
 * }
 * ```
 * Credential libraries need to implement only for custom types, as platform types are covered by this library.
 */
typealias JsonValueEncoder
        = (value: Any) -> JsonElement?

/**
 * Maps from [at.asitplus.iso.IssuerSignedItem.elementIdentifier] (the claim name) to its corresponding
 * [KSerializer].
 */
typealias ElementIdentifierToItemValueSerializerMap
        = Map<String, KSerializer<*>>

/**
 * Maps from ISO mDoc namespaces to the element identifier (the claim name) to its corresponding
 * [KSerializer].
 */
typealias IsoNamespaceToElementIdentifierToItemValueSerializerMap
        = Map<String, ElementIdentifierToItemValueSerializerMap>
