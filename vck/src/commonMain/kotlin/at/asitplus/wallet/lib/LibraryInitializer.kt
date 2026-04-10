@file:Suppress("unused")

package at.asitplus.wallet.lib

import at.asitplus.iso.CborCredentialSerializer
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.JsonCredentialSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.modules.SerializersModule

/**
 * Called by other libraries to register credential schemes with this library.
 */
object LibraryInitializer {

    /**
     * Register [credentialScheme] to be used with this library, e.g. in OpenID protocol implementations.
     */
    fun registerExtensionLibrary(
        credentialScheme: ConstantIndex.CredentialScheme,
    ) {
        AttributeIndex.registerAttributeType(credentialScheme)
    }

    /**
     * Register [credentialScheme] to be used with this library, e.g. in OpenID protocol implementations.
     *
     * Deprecated compatibility overload for credentials that still register a custom
     * [at.asitplus.wallet.lib.data.CredentialSubject] serializer.
     *
     * Implement `serializersModule` in this form:
     * ```
     * kotlinx.serialization.modules.SerializersModule {
     *     kotlinx.serialization.modules.polymorphic(CredentialSubject::class) {
     *         kotlinx.serialization.modules.subclass(YourCredential::class)
     *     }
     * }
     * ```
     *
     * @param serializersModule Definition of a polymorphic serializers module, see example in function doc.
     */
    @Deprecated(
        message = "Custom SerializersModule registration is no longer needed for VC JWT credentials. " +
            "Use registerExtensionLibrary(credentialScheme) instead.",
        replaceWith = ReplaceWith("registerExtensionLibrary(credentialScheme)"),
    )
    fun registerExtensionLibrary(
        credentialScheme: ConstantIndex.CredentialScheme,
        serializersModule: SerializersModule? = null
    ) {
        registerExtensionLibrary(credentialScheme)
        serializersModule?.let { JsonCredentialSerializer.registerSerializersModule(credentialScheme, it) }
    }

    /**
     * Register [credentialScheme] to be used with this library, e.g. in OpenID protocol implementations.
     * Used for credentials supporting [at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC],
     * which need to specify several functions to allow encoding any values
     * in [at.asitplus.iso.IssuerSignedItem].
     * See the function typealiases in [JsonValueEncoder] and [ElementIdentifierToItemValueSerializerMap]
     * for implementation notes.
     * Example for [jsonValueEncoder]:
     * ```
     * when (it) {
     *     is DrivingPrivilege -> vckJsonSerializer.encodeToJsonElement(it)
     *     is LocalDate -> vckJsonSerializer.encodeToJsonElement(it)
     *     is UInt -> vckJsonSerializer.encodeToJsonElement(it)
     *     else -> null
     * }
     * ```
     *
     * Example for [itemValueSerializerMap]:
     * ```
     * mapOf(
     *     MobileDrivingLicenceDataElements.BIRTH_DATE to LocalDate.serializer(),
     *     MobileDrivingLicenceDataElements.PORTRAIT to ByteArraySerializer(),
     * )
     * ```
     *
     * @param jsonValueEncoder used to describe the credential in input descriptors used in verifiable presentations,
     * e.g. when used in SIOPv2
     * @param itemValueSerializerMap used to actually serialize and deserialize `Any` object in
     * [at.asitplus.iso.IssuerSignedItemSerializer], with `elementIdentifier` as the key
     */
    fun registerExtensionLibrary(
        credentialScheme: ConstantIndex.CredentialScheme,
        jsonValueEncoder: JsonValueEncoder,
        itemValueSerializerMap: ElementIdentifierToItemValueSerializerMap = emptyMap(),
    ) {
        registerExtensionLibrary(credentialScheme)
        JsonCredentialSerializer.register(jsonValueEncoder)
        credentialScheme.isoNamespace?.let { CborCredentialSerializer.register(itemValueSerializerMap, it) }
    }

    /**
     * Register [credentialScheme] to be used with this library, e.g. in OpenID protocol implementations.
     *
     * Deprecated compatibility overload for credentials that still register a custom
     * [at.asitplus.wallet.lib.data.CredentialSubject] serializer for VC JWT usage.
     */
    @Deprecated(
        message = "Custom SerializersModule registration is no longer needed for VC JWT credentials. " +
            "Use registerExtensionLibrary(credentialScheme, jsonValueEncoder, itemValueSerializerMap) instead.",
        replaceWith = ReplaceWith(
            "registerExtensionLibrary(credentialScheme, jsonValueEncoder, itemValueSerializerMap)"
        ),
    )
    fun registerExtensionLibrary(
        credentialScheme: ConstantIndex.CredentialScheme,
        serializersModule: SerializersModule? = null,
        jsonValueEncoder: JsonValueEncoder,
        itemValueSerializerMap: ElementIdentifierToItemValueSerializerMap = emptyMap(),
    ) {
        registerExtensionLibrary(credentialScheme, jsonValueEncoder, itemValueSerializerMap)
        serializersModule?.let { JsonCredentialSerializer.registerSerializersModule(credentialScheme, it) }
    }

}

/**
 * Used to encode any value into a [JsonElement], implementation may be
 * ```
 * when (it) {
 *     is DrivingPrivilege -> vckJsonSerializer.encodeToJsonElement(it)
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
