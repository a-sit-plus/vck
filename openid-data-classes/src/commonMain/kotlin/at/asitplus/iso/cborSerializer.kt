package at.asitplus.iso

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.supreme.hash.digest
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.CompositeEncoder

object CborCredentialSerializer {

    private val decoderMap = mutableMapOf<String, Map<String, ItemValueDecoder>>()
    private val encoderMap = mutableMapOf<String, Map<String, ItemValueEncoder>>()
    private val serializerLookupMap = mutableMapOf<String, Map<String, KSerializer<*>>>()

    fun register(serializerMap: Map<String, KSerializer<*>>, isoNamespace: String) {
        decoderMap[isoNamespace] =
            serializerMap.map { (k, ser) ->
                k to decodeFun(ser)
            }.toMap()
        encoderMap[isoNamespace] =
            serializerMap.map { (k, ser) ->
                @Suppress("UNCHECKED_CAST")
                k to encodeFun(ser as KSerializer<Any>)
            }.toMap()
        serializerLookupMap[isoNamespace] = serializerMap
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
        serializerLookupMap[namespace]?.get(elementIdentifier)

    fun encode(
        namespace: String,
        elementIdentifier: String,
        descriptor: SerialDescriptor,
        index: Int,
        compositeEncoder: CompositeEncoder,
        value: Any,
    ) {
        encoderMap[namespace]?.get(elementIdentifier)?.invoke(descriptor, index, compositeEncoder, value)
    }

    fun decode(
        descriptor: SerialDescriptor,
        index: Int,
        compositeDecoder: CompositeDecoder,
        elementIdentifier: String,
        isoNamespace: String,
    ): Any? = decoderMap[isoNamespace]?.get(elementIdentifier)?.let {
        catchingUnwrapped { it.invoke(descriptor, index, compositeDecoder) }.getOrNull()
    }
}

fun ByteArray.stripCborTag(tag: Byte): ByteArray {
    val tagBytes = byteArrayOf(0xd8.toByte(), tag)
    return if (this.take(tagBytes.size).toByteArray().contentEquals(tagBytes)) {
        this.drop(tagBytes.size).toByteArray()
    } else {
        this
    }
}

fun ByteArray.wrapInCborTag(tag: Byte) = byteArrayOf(0xd8.toByte()) + byteArrayOf(tag) + this

fun ByteArray.sha256(): ByteArray = Digest.SHA256.digest(this)


private typealias ItemValueEncoder
        = (descriptor: SerialDescriptor, index: Int, compositeEncoder: CompositeEncoder, value: Any) -> Unit

private typealias ItemValueDecoder
        = (descriptor: SerialDescriptor, index: Int, compositeDecoder: CompositeDecoder) -> Any
