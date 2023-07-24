@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.cbor.CoseSigned
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.NAMESPACE_MDL
import io.github.aakira.napier.Napier
import io.matthewnelson.component.encoding.base16.encodeBase16
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.ByteStringWrapper
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

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

    fun serialize() = cborSerializer.encodeToByteArray(this)

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
            cborSerializer.decodeFromByteArray<DeviceRequest>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class DocRequest(
    @SerialName("itemsRequest")
    @Serializable(with = ByteStringWrapperItemsRequestSerializer::class)
    val itemsRequest: ByteStringWrapper<ItemsRequest>,
    @SerialName("readerAuth")
    val readerAuth: CoseSigned? = null,
) {
    fun extractReaderAuthentication() {
        // TODO is COSE_SIGN1
    }

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
    val namespaces: Map<String, Map<String, Boolean>>,
    @SerialName("requestInfo")
    val requestInfo: Map<String, String>? = null,
)

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
    fun serialize() = cborSerializer.encodeToByteArray(this)

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
            cborSerializer.decodeFromByteArray<DeviceResponse>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
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
)

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class IssuerSigned(
    @SerialName("nameSpaces")
    @ByteString
    val namespaces: Map<String, List<@Serializable(with = ByteStringWrapperIssuerSignedItemSerializer::class) ByteStringWrapper<IssuerSignedItem>>>? = null,
    @SerialName("issuerAuth")
    val issuerAuth: CoseSigned,
) {

    fun serialize() = cborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<IssuerSigned>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

    override fun toString(): String {
        return "IssuerSigned(namespaces=${namespaces?.map { it.key to it.value.map { it.value } }}, issuerAuth=$issuerAuth)"
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class IssuerSignedItem(
    @SerialName("digestID")
    val digestId: UInt,
    @SerialName("random")
    @ByteString
    val random: ByteArray,
    @SerialName("elementIdentifier")
    val elementIdentifier: String,
    @SerialName("elementValue")
    val elementValue: ElementValue,
) {

    fun serialize() = cborSerializer.encodeToByteArray(this)

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
                " random=${random.encodeBase16()}," +
                " elementIdentifier='$elementIdentifier'," +
                " elementValue=$elementValue)"
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<IssuerSignedItem>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}

// TODO Could this be anything else?
@Serializable(with = ElementValueSerializer::class)
data class ElementValue(
    val bytes: ByteArray? = null,
    val string: String? = null,
    val drivingPrivilege: List<DrivingPrivilege>? = null,
) {
    fun serialize() = cborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ElementValue

        if (bytes != null) {
            if (other.bytes == null) return false
            if (!bytes.contentEquals(other.bytes)) return false
        } else if (other.bytes != null) return false
        if (string != other.string) return false
        return drivingPrivilege == other.drivingPrivilege
    }

    override fun hashCode(): Int {
        var result = bytes?.contentHashCode() ?: 0
        result = 31 * result + (string?.hashCode() ?: 0)
        result = 31 * result + (drivingPrivilege?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "ElementValue(bytes=${bytes?.encodeBase16()}, string=$string, drivingPrivilege=$drivingPrivilege)"
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<ElementValue>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
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
    @ByteString
    val deviceAuth: DeviceAuth,
) {
    fun extractDeviceNameSpaces(): Map<String, Map<String, ElementValue>> {
        return cborSerializer.decodeFromByteArray(namespaces)
    }

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

    companion object {
        fun withDeviceNameSpaces(value: Map<String, Map<String, ElementValue>>, deviceAuth: DeviceAuth) =
            DeviceSigned(
                namespaces = cborSerializer.encodeToByteArray(value),
                deviceAuth = deviceAuth
            )
    }
}

data class DeviceNameSpaces(
    @SerialName(NAMESPACE_MDL)
    val entries: Map<String, ElementValue>
) {
    fun serialize() = cborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<DeviceNameSpaces>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
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
        val bytes = cborSerializer.encodeToByteArray(value.value)
        encoder.encodeSerializableValue(ByteArraySerializer(), bytes)
    }

    override fun deserialize(decoder: Decoder): ByteStringWrapper<ItemsRequest> {
        val bytes = decoder.decodeSerializableValue(ByteArraySerializer())
        return ByteStringWrapper(cborSerializer.decodeFromByteArray(bytes), bytes)
    }

}

object ByteStringWrapperIssuerSignedItemSerializer : KSerializer<ByteStringWrapper<IssuerSignedItem>> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteStringWrapperItemsRequestSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteStringWrapper<IssuerSignedItem>) {
        val bytes = cborSerializer.encodeToByteArray(value.value)
        encoder.encodeSerializableValue(ByteArraySerializer(), bytes)
    }

    override fun deserialize(decoder: Decoder): ByteStringWrapper<IssuerSignedItem> {
        val bytes = decoder.decodeSerializableValue(ByteArraySerializer())
        return ByteStringWrapper(cborSerializer.decodeFromByteArray(bytes), bytes)
    }

}

object ElementValueSerializer : KSerializer<ElementValue> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ElementValueSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ElementValue) {
        value.bytes?.let {
            encoder.encodeSerializableValue(ByteArraySerializer(), it)
        } ?: value.string?.let {
            encoder.encodeString(it)
        } ?: value.drivingPrivilege?.let {
            encoder.encodeSerializableValue(ListSerializer(DrivingPrivilege.serializer()), it)
        } ?: throw IllegalArgumentException("No value exists")
    }

    override fun deserialize(decoder: Decoder): ElementValue {
        runCatching {
            return ElementValue(bytes = decoder.decodeSerializableValue(ByteArraySerializer()))
        }
        runCatching {
            return ElementValue(string = decoder.decodeString())
        }
        runCatching {
            return ElementValue(
                drivingPrivilege = decoder.decodeSerializableValue(ListSerializer(DrivingPrivilege.serializer()))
            )
        }
        throw IllegalArgumentException("Could not decode instance of ElementValue")
    }

}
