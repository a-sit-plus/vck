package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SealedSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeCollection

/** The detached content signed by a single DocRequest.readerAuth (ISO/IEC 18013-5, 12.5). */
@Serializable
@CborArray
data class ReaderAuthentication(
    val type: String,
    val sessionTranscript: SessionTranscript,
    @ByteString
    @ValueTags(24U)
    val itemsRequestBytes: ByteArray,
) {

    companion object {
        fun detachedPayload(request: DocRequest, transcript: SessionTranscript): ByteArray =
            coseCompliantSerializer.encodeToByteArray(
                coseCompliantSerializer.encodeToByteArray(
                    ReaderAuthentication("ReaderAuthentication", transcript, request.itemsRequest.originalBytes())
                )
            ).wrapInCborTag(24)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ReaderAuthentication

        if (type != other.type) return false
        if (sessionTranscript != other.sessionTranscript) return false
        if (!itemsRequestBytes.contentEquals(other.itemsRequestBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + sessionTranscript.hashCode()
        result = 31 * result + itemsRequestBytes.contentHashCode()
        return result
    }
}

/**
 * The detached content signed by DeviceRequest.readerAuthAll (ISO/IEC 18013-5, 12.5).
 * [deviceRequestInfoBytes] is `DeviceRequestInfoBytes / null`, so only a present value is tagged,
 * see [ReaderAuthenticationAllSerializer].
 */
@Serializable(with = ReaderAuthenticationAllSerializer::class)
data class ReaderAuthenticationAll(
    val type: String,
    val sessionTranscript: SessionTranscript,
    val itemsRequestBytesAll: TaggedCborBytesList,
    val deviceRequestInfoBytes: ByteArray?,
) {

    companion object {
        fun detachedPayload(request: DeviceRequest, transcript: SessionTranscript): ByteArray =
            coseCompliantSerializer.encodeToByteArray(
                coseCompliantSerializer.encodeToByteArray(
                    ReaderAuthenticationAll(
                        "ReaderAuthenticationAll",
                        transcript,
                        TaggedCborBytesList(request.docRequests.map { it.itemsRequest.originalBytes() }),
                        request.deviceRequestInfo?.originalBytes(),
                    )
                )
            ).wrapInCborTag(24)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ReaderAuthenticationAll

        if (type != other.type) return false
        if (sessionTranscript != other.sessionTranscript) return false
        if (itemsRequestBytesAll != other.itemsRequestBytesAll) return false
        if (!deviceRequestInfoBytes.contentEquals(other.deviceRequestInfoBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + sessionTranscript.hashCode()
        result = 31 * result + itemsRequestBytesAll.hashCode()
        result = 31 * result + (deviceRequestInfoBytes?.contentHashCode() ?: 0)
        return result
    }
}

@Serializable
@CborArray
private class TaggedReaderAuthenticationAll(
    val type: String,
    val sessionTranscript: SessionTranscript,
    val itemsRequestBytesAll: TaggedCborBytesList,
    @ByteString @ValueTags(24U) val deviceRequestInfoBytes: ByteArray,
)

@Serializable
@CborArray
private class UntaggedReaderAuthenticationAll(
    val type: String,
    val sessionTranscript: SessionTranscript,
    val itemsRequestBytesAll: TaggedCborBytesList,
    @ByteString val deviceRequestInfoBytes: ByteArray?,
)

/**
 * Encodes a present `deviceRequestInfoBytes` as a tag-24 byte string and an absent one as plain `null`.
 * A `@ValueTags` annotation on a nullable property would tag `null` as well, i.e. `#6.24(null)`.
 * Decoding reads the untagged shape, as tag 24 is only verified when the descriptor declares it.
 */
object ReaderAuthenticationAllSerializer : KSerializer<ReaderAuthenticationAll> {
    @OptIn(ExperimentalSerializationApi::class)
    override val descriptor: SerialDescriptor =
        SerialDescriptor("at.asitplus.iso.ReaderAuthenticationAll", UntaggedReaderAuthenticationAll.serializer().descriptor)

    override fun serialize(encoder: Encoder, value: ReaderAuthenticationAll) {
        val deviceRequestInfoBytes = value.deviceRequestInfoBytes
        if (deviceRequestInfoBytes != null) {
            encoder.encodeSerializableValue(
                TaggedReaderAuthenticationAll.serializer(),
                TaggedReaderAuthenticationAll(
                    value.type,
                    value.sessionTranscript,
                    value.itemsRequestBytesAll,
                    deviceRequestInfoBytes
                )
            )
        } else {
            encoder.encodeSerializableValue(
                UntaggedReaderAuthenticationAll.serializer(),
                UntaggedReaderAuthenticationAll(value.type, value.sessionTranscript, value.itemsRequestBytesAll, null)
            )
        }
    }

    override fun deserialize(decoder: Decoder): ReaderAuthenticationAll =
        decoder.decodeSerializableValue(UntaggedReaderAuthenticationAll.serializer()).let {
            ReaderAuthenticationAll(it.type, it.sessionTranscript, it.itemsRequestBytesAll, it.deviceRequestInfoBytes)
        }
}

private inline fun <reified T> ByteStringWrapper<T>.originalBytes(): ByteArray =
    serialized.takeIf { it.isNotEmpty() } ?: coseCompliantSerializer.encodeToByteArray(value)

@Serializable(with = TaggedCborBytesListSerializer::class)
data class TaggedCborBytesList(val values: List<ByteArray>) {
    override fun equals(other: Any?): Boolean = other is TaggedCborBytesList &&
            values.size == other.values.size && values.zip(other.values).all { (a, b) -> a.contentEquals(b) }

    override fun hashCode(): Int = values.fold(1) { hash, bytes -> 31 * hash + bytes.contentHashCode() }
}

/** Encodes each original CBOR byte string as a tag-24 byte string, without re-encoding its contents. */
object TaggedCborBytesListSerializer : KSerializer<TaggedCborBytesList> {
    @OptIn(ExperimentalSerializationApi::class, SealedSerializationApi::class)
    override val descriptor: SerialDescriptor = object : SerialDescriptor by
    kotlinx.serialization.builtins.ListSerializer(ByteArraySerializer()).descriptor {
        override fun getElementAnnotations(index: Int): List<Annotation> = listOf(ValueTags(24U))
    }

    override fun serialize(encoder: Encoder, value: TaggedCborBytesList) {
        encoder.encodeCollection(descriptor, value.values.size) {
            value.values.forEachIndexed { index, bytes ->
                encodeSerializableElement(descriptor, index, ByteArraySerializer(), bytes)
            }
        }
    }

    override fun deserialize(decoder: Decoder): TaggedCborBytesList {
        val values = mutableListOf<ByteArray>()
        decoder.decodeStructure(descriptor) {
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                values += decodeSerializableElement(descriptor, index, ByteArraySerializer())
            }
        }
        return TaggedCborBytesList(values)
    }
}
