@file:Suppress("unused")

package at.asitplus.wallet.lib

import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.JsonCredentialSerializer
import at.asitplus.wallet.lib.iso.CborCredentialSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.modules.SerializersModule

/**
 * Called by other libraries to extend credentials by subclassing [at.asitplus.wallet.lib.data.CredentialSubject].
 */
object LibraryInitializer {

    /**
     * Register [credentialScheme] to be used with this library, e.g. in OpenID protocol implementations.
     *
     * Specify [serializersModule] if the credential scheme supports [ConstantIndex.CredentialRepresentation.PLAIN_JWT],
     * i.e. it implements a subclass of [at.asitplus.wallet.lib.data.CredentialSubject] that needs to be de/serialized.
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
    fun registerExtensionLibrary(
        credentialScheme: ConstantIndex.CredentialScheme,
        serializersModule: SerializersModule? = null
    ) {
        AttributeIndex.registerAttributeType(credentialScheme)
        serializersModule?.let { JsonCredentialSerializer.registerSerializersModule(credentialScheme::class, it) }
    }

    /**
     * Register [credentialScheme] to be used with this library, e.g. in OpenID protocol implementations.
     * Used for credentials supporting [at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC],
     * which need to specify several functions to allow encoding any values
     * in [at.asitplus.wallet.lib.iso.IssuerSignedItem].
     * See the function typealiases in [JsonValueEncoder] and [ElementIdentifierToItemValueSerializerMap]
     * for implementation notes.
     *
     *
     * Example for [serializersModule]:
     * ```
     * kotlinx.serialization.modules.SerializersModule {
     *     kotlinx.serialization.modules.polymorphic(CredentialSubject::class) {
     *         kotlinx.serialization.modules.subclass(YourCredential::class)
     *     }
     * }
     * ```
     *
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
     * @param serializersModule needed if supporting [ConstantIndex.CredentialRepresentation.PLAIN_JWT],
     * i.e. it implements a subclass of [at.asitplus.wallet.lib.data.CredentialSubject] that needs to be de/serialized.
     * @param jsonValueEncoder used to describe the credential in input descriptors used in verifiable presentations,
     * e.g. when used in SIOPv2
     * @param itemValueSerializerMap used to actually serialize and deserialize `Any` object in
     * [at.asitplus.wallet.lib.iso.IssuerSignedItemSerializer], with `elementIdentifier` as the key
     */
    fun registerExtensionLibrary(
        credentialScheme: ConstantIndex.CredentialScheme,
        serializersModule: SerializersModule? = null,
        jsonValueEncoder: JsonValueEncoder,
        itemValueSerializerMap: ElementIdentifierToItemValueSerializerMap = emptyMap(),
    ) {
        registerExtensionLibrary(credentialScheme, serializersModule)
        JsonCredentialSerializer.register(jsonValueEncoder)
        credentialScheme.isoNamespace?.let { CborCredentialSerializer.register(itemValueSerializerMap, it) }
    }

}

/**
 * Used to encode any value into a [JsonElement], implementation may be
 * ```
 * when (it) {
 *     is DrivingPrivilege -> vckJsonSerializer.encodeToJsonElement(it)
 *     is LocalDate -> vckJsonSerializer.encodeToJsonElement(it)
 *     is UInt -> vckJsonSerializer.encodeToJsonElement(it)
 *     else -> null
 * }
 * ```
 */
typealias JsonValueEncoder
        = (value: Any) -> JsonElement?

/**
 * Maps from [at.asitplus.wallet.lib.iso.IssuerSignedItem.elementIdentifier] (the claim name) to its corresponding
 * [KSerializer].
 */
typealias ElementIdentifierToItemValueSerializerMap
        = Map<String, KSerializer<*>>