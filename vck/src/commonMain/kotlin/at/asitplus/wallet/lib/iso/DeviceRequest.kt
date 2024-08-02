@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.cosef.CoseSigned
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ByteString
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.descriptors.listSerialDescriptor
import kotlinx.serialization.descriptors.mapSerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeCollection
import kotlinx.serialization.encoding.encodeStructure
import okio.ByteString.Companion.toByteString

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class DeviceRequest(
    @SerialName("version")
    val version: String,
    @SerialName("docRequests")
    val docRequests: Array<DocRequest>,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DeviceRequest

        if (version != other.version) return false
        return docRequests.contentEquals(other.docRequests)
    }

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + docRequests.contentHashCode()
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<DeviceRequest>(it)
        }.wrap()
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class DocRequest(
    @SerialName("itemsRequest")
    @Serializable(with = ByteStringWrapperItemsRequestSerializer::class)
    @ValueTags(24U)
    val itemsRequest: ByteStringWrapper<ItemsRequest>,
    @SerialName("readerAuth")
    val readerAuth: CoseSigned? = null,
) {
    override fun toString(): String {
        return "DocRequest(itemsRequest=${itemsRequest.value}, readerAuth=$readerAuth)"
    }

}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class ItemsRequest(
    @SerialName("docType")
    val docType: String,
    @SerialName("nameSpaces")
    val namespaces: Map<String, ItemsRequestList>,
    @SerialName("requestInfo")
    val requestInfo: Map<String, String>? = null,
)


/**
 * Convenience class with a custom serializer ([ItemsRequestListSerializer]) to prevent
 * usage of the type `Map<String, Map<String, Boolean>>` in [ItemsRequest.namespaces].
 */
@Serializable(with = ItemsRequestListSerializer::class)
data class ItemsRequestList(
    val entries: List<SingleItemsRequest>
)

/**
 * Convenience class with a custom serializer ([ItemsRequestListSerializer]) to prevent
 * usage of the type `Map<String, Map<String, Boolean>>` in [ItemsRequest.namespaces].
 */
data class SingleItemsRequest(
    val key: String,
    val value: Boolean,
)

/**
 * Serializes [ItemsRequestList.entries] as an "inline map",
 * having [SingleItemsRequest.key] as the map key and [SingleItemsRequest.value] as the map value,
 * for the map represented by [ItemsRequestList].
 */
object ItemsRequestListSerializer : KSerializer<ItemsRequestList> {

    override val descriptor: SerialDescriptor = mapSerialDescriptor(
        keyDescriptor = PrimitiveSerialDescriptor("key", PrimitiveKind.INT),
        valueDescriptor = listSerialDescriptor<Byte>(),
    )

    override fun serialize(encoder: Encoder, value: ItemsRequestList) {
        encoder.encodeStructure(descriptor) {
            var index = 0
            value.entries.forEach {
                this.encodeStringElement(descriptor, index++, it.key)
                this.encodeBooleanElement(descriptor, index++, it.value)
            }
        }
    }

    override fun deserialize(decoder: Decoder): ItemsRequestList {
        val entries = mutableListOf<SingleItemsRequest>()
        decoder.decodeStructure(descriptor) {
            lateinit var key: String
            var value: Boolean
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) {
                    break
                } else if (index % 2 == 0) {
                    key = decodeStringElement(descriptor, index)
                } else if (index % 2 == 1) {
                    value = decodeBooleanElement(descriptor, index)
                    entries += SingleItemsRequest(key, value)
                }
            }
        }
        return ItemsRequestList(entries)
    }
}


/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class DeviceResponse(
    @SerialName("version")
    val version: String,
    @SerialName("documents")
    val documents: Array<Document>? = null,
    @SerialName("documentErrors")
    val documentErrors: Array<Pair<String, UInt>>? = null,
    @SerialName("status")
    val status: UInt,
) {
    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DeviceResponse

        if (version != other.version) return false
        if (documents != null) {
            if (other.documents == null) return false
            if (!documents.contentEquals(other.documents)) return false
        } else if (other.documents != null) return false
        if (documentErrors != null) {
            if (other.documentErrors == null) return false
            if (!documentErrors.contentEquals(other.documentErrors)) return false
        } else if (other.documentErrors != null) return false
        return status == other.status
    }

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + (documents?.contentHashCode() ?: 0)
        result = 31 * result + (documentErrors?.contentHashCode() ?: 0)
        result = 31 * result + status.hashCode()
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<DeviceResponse>(it)
        }.wrap()
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class Document(
    @SerialName("docType")
    val docType: String,
    @SerialName("issuerSigned")
    val issuerSigned: IssuerSigned,
    @SerialName("deviceSigned")
    val deviceSigned: DeviceSigned,
    @SerialName("errors")
    val errors: Map<String, Map<String, Int>>? = null,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<Document>(it)
        }.wrap()
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class IssuerSigned(
    @SerialName("nameSpaces")
    val namespaces: Map<String, IssuerSignedList>? = null,
    @SerialName("issuerAuth")
    val issuerAuth: CoseSigned,
) {

    fun getIssuerAuthPayloadAsMso() = issuerAuth.payload?.stripCborTag(24)
        ?.let { vckCborSerializer.decodeFromByteArray(ByteStringWrapperMobileSecurityObjectSerializer, it).value }

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<IssuerSigned>(it)
        }.wrap()
    }
}


/**
 * Convenience class with a custom serializer ([IssuerSignedListSerializer]) to prevent
 * usage of the type `Map<String, List<ByteStringWrapper<IssuerSignedItem>>>` in [IssuerSigned.namespaces].
 */
@Serializable(with = IssuerSignedListSerializer::class)
data class IssuerSignedList(
    val entries: List<ByteStringWrapper<IssuerSignedItem>>
) {
    override fun toString(): String {
        return "IssuerSignedList(entries=${entries.map { it.value }})"
    }

    companion object {
        fun withItems(list: List<IssuerSignedItem>) = IssuerSignedList(
            // TODO verify serialization of this
            list.map { ByteStringWrapper(it, vckCborSerializer.encodeToByteArray(it).wrapInCborTag(24)) }
        )
    }
}

/**
 * Serializes [IssuerSignedList.entries] as an "inline list",
 * having serialized instances of [IssuerSignedItem] as the values.
 */
object IssuerSignedListSerializer : KSerializer<IssuerSignedList> {

    override val descriptor: SerialDescriptor = object : SerialDescriptor {
        @ExperimentalSerializationApi
        override val elementsCount: Int = 1

        @ExperimentalSerializationApi
        override val kind: SerialKind = StructureKind.LIST

        @ExperimentalSerializationApi
        override val serialName: String = "kotlin.collections.ArrayList"

        @ExperimentalSerializationApi
        override fun getElementAnnotations(index: Int): List<Annotation> {
            return listOf(ValueTags(24U))
        }

        @ExperimentalSerializationApi
        override fun getElementDescriptor(index: Int): SerialDescriptor {
            return Byte.serializer().descriptor
        }

        @ExperimentalSerializationApi
        override fun getElementIndex(name: String): Int {
            return name.toInt()
        }

        @ExperimentalSerializationApi
        override fun getElementName(index: Int): String {
            return index.toString()
        }

        @ExperimentalSerializationApi
        override fun isElementOptional(index: Int): Boolean {
            return false
        }
    }


    override fun serialize(encoder: Encoder, value: IssuerSignedList) {
        var index = 0
        encoder.encodeCollection(descriptor, value.entries.size) {
            value.entries.forEach {
                encodeSerializableElement(descriptor, index++, ByteArraySerializer(), it.value.serialize())
            }
        }
    }

    override fun deserialize(decoder: Decoder): IssuerSignedList {
        val entries = mutableListOf<ByteStringWrapper<IssuerSignedItem>>()
        decoder.decodeStructure(descriptor) {
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) {
                    break
                } else {
                    val readBytes = decoder.decodeSerializableValue(ByteArraySerializer())
                    entries += ByteStringWrapper(
                        value = IssuerSignedItem.deserialize(readBytes).getOrThrow(),
                        serialized = readBytes
                    )
                }
            }
        }
        return IssuerSignedList(entries)
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable(with = IssuerSignedItemSerializer::class)
data class IssuerSignedItem(
    @SerialName("digestID")
    val digestId: UInt,
    @SerialName("random")
    @ByteString
    val random: ByteArray,
    @SerialName("elementIdentifier")
    val elementIdentifier: String,
    @SerialName("elementValue")
    val elementValue: Any,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IssuerSignedItem

        if (digestId != other.digestId) return false
        if (!random.contentEquals(other.random)) return false
        if (elementIdentifier != other.elementIdentifier) return false
        return elementValue == other.elementValue
    }

    override fun hashCode(): Int {
        var result = digestId.hashCode()
        result = 31 * result + random.contentHashCode()
        result = 31 * result + elementIdentifier.hashCode()
        result = 31 * result + elementValue.hashCode()
        return result
    }

    override fun toString(): String {
        return "IssuerSignedItem(digestId=$digestId," +
                " random=${random.encodeToString(Base16(strict = true))}," +
                " elementIdentifier='$elementIdentifier'," +
                " elementValue=$elementValue)"
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<IssuerSignedItem>(it)
        }.wrap()
    }
}


/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class DeviceSigned(
    @SerialName("nameSpaces")
    @ByteString
    @ValueTags(24U)
    val namespaces: ByteArray,
    @SerialName("deviceAuth")
    val deviceAuth: DeviceAuth,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DeviceSigned

        if (!namespaces.contentEquals(other.namespaces)) return false
        return deviceAuth == other.deviceAuth
    }

    override fun hashCode(): Int {
        var result = namespaces.contentHashCode()
        result = 31 * result + deviceAuth.hashCode()
        return result
    }

}


/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class DeviceAuth(
    @SerialName("deviceSignature")
    val deviceSignature: CoseSigned? = null,
    @SerialName("deviceMac")
    val deviceMac: CoseSigned? = null, // TODO is COSE_Mac0
)


object ByteStringWrapperItemsRequestSerializer : KSerializer<ByteStringWrapper<ItemsRequest>> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteStringWrapperItemsRequestSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteStringWrapper<ItemsRequest>) {
        val bytes = vckCborSerializer.encodeToByteArray(value.value)
        encoder.encodeSerializableValue(ByteArraySerializer(), bytes)
    }

    override fun deserialize(decoder: Decoder): ByteStringWrapper<ItemsRequest> {
        val bytes = decoder.decodeSerializableValue(ByteArraySerializer())
        return ByteStringWrapper(vckCborSerializer.decodeFromByteArray(bytes), bytes)
    }

}

fun ByteArray.stripCborTag(tag: Byte) = this.dropWhile { it == 0xd8.toByte() }.dropWhile { it == tag }.toByteArray()

fun ByteArray.wrapInCborTag(tag: Byte) = byteArrayOf(0xd8.toByte()) + byteArrayOf(tag) + this

fun ByteArray.sha256(): ByteArray = toByteString().sha256().toByteArray()
