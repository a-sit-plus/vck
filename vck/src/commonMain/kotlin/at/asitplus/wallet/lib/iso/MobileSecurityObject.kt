@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.cosef.CoseKey
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Instant
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.listSerialDescriptor
import kotlinx.serialization.descriptors.mapSerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for MSO (9.1.2.4)
 */
@Serializable
data class MobileSecurityObject(
    @SerialName("version")
    val version: String,
    @SerialName("digestAlgorithm")
    val digestAlgorithm: String,
    @SerialName("valueDigests")
    val valueDigests: Map<String, ValueDigestList>,
    @SerialName("deviceKeyInfo")
    val deviceKeyInfo: DeviceKeyInfo,
    @SerialName("docType")
    val docType: String,
    @SerialName("validityInfo")
    val validityInfo: ValidityInfo,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    fun serializeForIssuerAuth() =
        vckCborSerializer.encodeToByteArray(ByteStringWrapperMobileSecurityObjectSerializer, ByteStringWrapper(this))
            .wrapInCborTag(24)

    companion object {
        fun deserializeFromIssuerAuth(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray(
                ByteStringWrapperMobileSecurityObjectSerializer,
                it.stripCborTag(24)
            ).value
        }.wrap()

        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<MobileSecurityObject>(it)
        }.wrap()
    }
}

/**
 * Convenience class with a custom serializer ([ValueDigestListSerializer]) to prevent
 * usage of the type `Map<String, Map<UInt, ByteArray>>` in [MobileSecurityObject.valueDigests].
 */
@Serializable(with = ValueDigestListSerializer::class)
data class ValueDigestList(
    val entries: List<ValueDigest>
)

/**
 * Convenience class with a custom serializer ([ValueDigestListSerializer]) to prevent
 * usage of the type `Map<String, Map<UInt, ByteArray>>` in [MobileSecurityObject.valueDigests].
 */
data class ValueDigest(
    val key: UInt,
    val value: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ValueDigest

        if (key != other.key) return false
        return value.contentEquals(other.value)
    }

    override fun hashCode(): Int {
        var result = key.hashCode()
        result = 31 * result + value.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "MobileSecurityObjectNamespaceEntry(key=$key, value=${value.encodeToString(Base16(strict = true))})"
    }

    companion object {
        fun fromIssuerSigned(namspace:String, value: IssuerSignedItem) = ValueDigest(
            value.digestId,
            value.serialize(namspace).wrapInCborTag(24).sha256()
        )
    }
}

/**
 * Serialized the [ValueDigestList.entries] as an "inline map",
 * meaning [ValueDigest.key] is the map key and [ValueDigest.value] the map value,
 * for the map represented by [ValueDigestList]
 */
object ValueDigestListSerializer : KSerializer<ValueDigestList> {

    override val descriptor: SerialDescriptor = mapSerialDescriptor(
        keyDescriptor = PrimitiveSerialDescriptor("key", PrimitiveKind.INT),
        valueDescriptor = listSerialDescriptor<Byte>(),
    )

    override fun serialize(encoder: Encoder, value: ValueDigestList) {
        encoder.encodeStructure(descriptor) {
            var index = 0
            value.entries.forEach {
                this.encodeIntElement(descriptor, index++, it.key.toInt())
                // TODO Values need to be tagged with 24 ... resulting in prefix D818
                this.encodeSerializableElement(descriptor, index++, ByteArraySerializer(), it.value)
            }
        }
    }

    override fun deserialize(decoder: Decoder): ValueDigestList {
        val entries = mutableListOf<ValueDigest>()
        decoder.decodeStructure(descriptor) {
            var key = 0
            var value: ByteArray
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) {
                    break
                } else if (index % 2 == 0) {
                    key = decodeIntElement(descriptor, index)
                } else if (index % 2 == 1) {
                    value = decodeSerializableElement(descriptor, index, ByteArraySerializer())
                    entries += ValueDigest(key.toUInt(), value)
                }
            }
        }
        return ValueDigestList(entries)
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for MSO (9.1.2.4)
 */
@Serializable
data class DeviceKeyInfo(
    @SerialName("deviceKey")
    val deviceKey: CoseKey,
    @SerialName("keyAuthorizations")
    val keyAuthorizations: KeyAuthorization? = null,
    @SerialName("keyInfo")
    val keyInfo: Map<Int, String>? = null,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<DeviceKeyInfo>(it)
        }.wrap()
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for MSO (9.1.2.4)
 */
@Serializable
data class KeyAuthorization(
    @SerialName("nameSpaces")
    val namespaces: Array<String>? = null,
    @SerialName("dataElements")
    val dataElements: Map<String, Array<String>>? = null,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KeyAuthorization

        if (namespaces != null) {
            if (other.namespaces == null) return false
            if (!namespaces.contentEquals(other.namespaces)) return false
        } else if (other.namespaces != null) return false
        return dataElements == other.dataElements
    }

    override fun hashCode(): Int {
        var result = namespaces?.contentHashCode() ?: 0
        result = 31 * result + (dataElements?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<KeyAuthorization>(it)
        }.wrap()
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for MSO (9.1.2.4)
 */
@Serializable
data class ValidityInfo(
    @SerialName("signed")
    val signed: Instant,
    @SerialName("validFrom")
    val validFrom: Instant,
    @SerialName("validUntil")
    val validUntil: Instant,
    @SerialName("expectedUpdate")
    val expectedUpdate: Instant? = null,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<ValidityInfo>(it)
        }.wrap()
    }
}


object ByteStringWrapperMobileSecurityObjectSerializer : KSerializer<ByteStringWrapper<MobileSecurityObject>> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteStringWrapperMobileSecurityObjectSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteStringWrapper<MobileSecurityObject>) {
        val bytes = vckCborSerializer.encodeToByteArray(value.value)
        encoder.encodeSerializableValue(ByteArraySerializer(), bytes)
    }

    override fun deserialize(decoder: Decoder): ByteStringWrapper<MobileSecurityObject> {
        val bytes = decoder.decodeSerializableValue(ByteArraySerializer())
        return ByteStringWrapper(vckCborSerializer.decodeFromByteArray(bytes), bytes)
    }

}
