@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlinx.serialization.modules.SerializersModule
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
@Serializable(with = DocumentSerializer::class)
data class Document(
    @SerialName("docType")
    val docType: String, // TODO this is relevant for deserializing the elementValue of IssuerSignedItem
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

object DocumentSerializer : KSerializer<Document> {
    private val errorSerializer =
        MapSerializer(String.serializer(), MapSerializer(String.serializer(), Int.serializer()))
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Document") {
        element("docType", String.serializer().descriptor)
        element("issuerSigned", IssuerSigned.serializer().descriptor)
        element("deviceSigned", DeviceSigned.serializer().descriptor)
        element("errors", errorSerializer.descriptor)
    }

    override fun deserialize(decoder: Decoder): Document = decoder.decodeStructure(descriptor) {

        val docType = decodeStringElement(descriptor, decodeAndCheckPropertyName("docType"))
        val issuerSigned = DoctypeAwareCompositeDecoder(this, docType, serializersModule).decodeSerializableElement(
            descriptor,
            decodeAndCheckPropertyName("issuerSigned"),
            IssuerSigned.serializer()
        )
        val deviceSigned = decodeSerializableElement(
            descriptor,
            decodeAndCheckPropertyName("deviceSigned"),
            DeviceSigned.serializer()
        )
        val errors =
            decodeNullableSerializableElement(descriptor, decodeAndCheckPropertyName("errors"), errorSerializer)
        Document(docType, issuerSigned, deviceSigned, errors)
    }


    override fun serialize(encoder: Encoder, value: Document) {
        encoder.encodeStructure(descriptor) {
            encodeStringElement(descriptor, 0, value.docType)
            encodeSerializableElement(descriptor, 1, IssuerSigned.serializer(), value.issuerSigned)
            encodeSerializableElement(descriptor, 2, DeviceSigned.serializer(), value.deviceSigned)
            encodeNullableSerializableElement(descriptor, 3, errorSerializer, value.errors)
        }
    }

    private fun CompositeDecoder.decodeAndCheckPropertyName(expected: String): Int {
        val name = decodeStringElement(descriptor, 0)
        if (expected != expected) throw SerializationException("expected \"$expected\" but was \"$name\"")
        return descriptor.getElementIndex(name)
    }
}


class DocTypeAwareDecoder(val decoder: Decoder, var docType: String) : Decoder by decoder {
    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {
        return DoctypeAwareCompositeDecoder(decoder.beginStructure(descriptor), docType, serializersModule)
    }
}

class DoctypeAwareCompositeDecoder(
    private val compositeDecoder: CompositeDecoder, val docType: String,
    override val serializersModule: SerializersModule
) : CompositeDecoder by compositeDecoder {
    override fun <T> decodeSerializableElement(
        descriptor: SerialDescriptor,
        index: Int,
        deserializer: DeserializationStrategy<T>,
        previousValue: T?
    ): T {
        return compositeDecoder.decodeSerializableElement(
            descriptor,
            index,
            DocTypeAwareSerializationStrategy(docType, deserializer),
            previousValue
        )
    }

    override fun <T : Any> decodeNullableSerializableElement(
        descriptor: SerialDescriptor,
        index: Int,
        deserializer: DeserializationStrategy<T?>,
        previousValue: T?
    ): T? {
        return compositeDecoder.decodeNullableSerializableElement(
            descriptor,
            index,
            DocTypeAwareSerializationStrategy(docType, deserializer),
            previousValue
        )
    }

    class DocTypeAwareSerializationStrategy<T>(val docType: String, val strategy: DeserializationStrategy<T>) :
        DeserializationStrategy<T> by strategy {
        override fun deserialize(decoder: Decoder): T {
            return strategy.deserialize(DocTypeAwareDecoder(decoder, docType))
        }
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
                    //TODO here we are docType-aware!
                    if (this !is DoctypeAwareCompositeDecoder) throw SerializationException("docType unknown!")
                    entries += ByteStringWrapper(
                        value = IssuerSignedItem.deserialize(readBytes, docType = docType).getOrThrow(),
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

private object DontUse : IssuerSignedItemSerializer("") {}

@Serializable(with = DontUse::class)
data class IssuerSignedItem(
    @SerialName("digestID")
    val digestId: UInt,
    @SerialName("random")
    @ByteString
    val random: ByteArray,
    @SerialName("elementIdentifier")
    val elementIdentifier: String,
    @SerialName("elementValue")
    @ValueTags(1004uL)
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
        fun deserialize(it: ByteArray, docType: String) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray(IssuerSignedItemSerializer(docType), it)
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
