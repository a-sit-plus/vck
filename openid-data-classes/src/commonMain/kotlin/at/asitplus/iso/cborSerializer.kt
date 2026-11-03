package at.asitplus.iso

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.supreme.hash.digest
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.CompositeEncoder
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update

@OptIn(ExperimentalAtomicApi::class)
object CborCredentialSerializer {

    private data class NamespaceSerializers(
        val decoders: Map<String, ItemValueDecoder>,
        val encoders: Map<String, ItemValueEncoder>,
        val serializers: Map<String, KSerializer<*>>,
    )

    private val serializersByNamespaceRef = AtomicReference(emptyMap<String, NamespaceSerializers>())

    fun register(serializerMap: Map<String, KSerializer<*>>, isoNamespace: String) {
        val namespaceSerializers = NamespaceSerializers(
            decoders = serializerMap.mapValues { (_, serializer) -> decodeFun(serializer) },
            encoders = serializerMap.mapValues { (_, serializer) ->
                @Suppress("UNCHECKED_CAST")
                encodeFun(serializer as KSerializer<Any>)
            },
            serializers = serializerMap,
        )
        serializersByNamespaceRef.update { it + (isoNamespace to namespaceSerializers) }
    }

    private fun decodeFun(ser: KSerializer<*>) =
        { descriptor: SerialDescriptor, index: Int, compositeDecoder: CompositeDecoder ->
            compositeDecoder.decodeSerializableElement(descriptor, index, ser)!!
        }

    private fun encodeFun(ser: KSerializer<Any>) =
        { descriptor: SerialDescriptor, index: Int, compositeEncoder: CompositeEncoder, value: Any ->
            compositeEncoder.encodeSerializableElement(descriptor, index, ser, value)
        }

    fun lookupSerializer(namespace: String, elementIdentifier: String): KSerializer<*>? =
        serializersByNamespaceRef.load()[namespace]?.serializers?.get(elementIdentifier)

    fun encode(
        namespace: String,
        elementIdentifier: String,
        descriptor: SerialDescriptor,
        index: Int,
        compositeEncoder: CompositeEncoder,
        value: Any,
    ) {
        serializersByNamespaceRef.load()[namespace]?.encoders?.get(elementIdentifier)
            ?.invoke(descriptor, index, compositeEncoder, value)
    }

    fun decode(
        descriptor: SerialDescriptor,
        index: Int,
        compositeDecoder: CompositeDecoder,
        elementIdentifier: String,
        isoNamespace: String,
    ): Any? = serializersByNamespaceRef.load()[isoNamespace]?.decoders?.get(elementIdentifier)?.let {
        catchingUnwrapped { it.invoke(descriptor, index, compositeDecoder) }.getOrNull()
    }
}

fun ByteArray.stripCborTag(tag: Byte): ByteArray {
    val tagBytes = cborTagPrefix(tag)
    return if (this.take(tagBytes.size).toByteArray().contentEquals(tagBytes)) {
        this.drop(tagBytes.size).toByteArray()
    } else {
        this
    }
}

/** Encodes a CBOR tag number from 0 to 255 using its shortest head (RFC 8949, Section 3). */
private fun cborTagPrefix(tag: Byte): ByteArray {
    val number = tag.toUByte().toInt()
    return if (number < 24) {
        byteArrayOf((0xc0 or number).toByte())
    } else {
        byteArrayOf(0xd8.toByte(), tag)
    }
}

fun ByteArray.wrapInCborTag(tag: Byte) = cborTagPrefix(tag) + this

fun ByteArray.sha256(): ByteArray = Digest.SHA256.digest(this)


private typealias ItemValueEncoder
        = (descriptor: SerialDescriptor, index: Int, compositeEncoder: CompositeEncoder, value: Any) -> Unit

private typealias ItemValueDecoder
        = (descriptor: SerialDescriptor, index: Int, compositeDecoder: CompositeDecoder) -> Any
