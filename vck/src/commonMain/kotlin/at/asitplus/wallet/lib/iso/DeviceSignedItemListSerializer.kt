package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.data.InstantStringSerializer
import io.github.aakira.napier.Napier
import kotlinx.datetime.Instant
import kotlinx.datetime.LocalDate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.mapSerialDescriptor
import kotlinx.serialization.encoding.*

/**
 * Serializes [DeviceSignedItemList.entries] as an "inline map",
 * having serialized instances of [DeviceSignedItem] as the values.
 */
open class DeviceSignedItemListSerializer(private val namespace: String) :
    KSerializer<DeviceSignedItemList> {

    override val descriptor: SerialDescriptor = mapSerialDescriptor(
        PrimitiveSerialDescriptor("key", PrimitiveKind.STRING),
        PrimitiveSerialDescriptor("value", PrimitiveKind.STRING)
    )

    override fun serialize(encoder: Encoder, value: DeviceSignedItemList) {
        encoder.encodeStructure(descriptor) {
            var index = 0
            value.entries.forEach {
                this.encodeStringElement(descriptor, index++, it.key)
                this.encodeAnything(it, index++)
            }
        }
    }


    private fun CompositeEncoder.encodeAnything(value: DeviceSignedItem, index: Int) {
        val elementValueSerializer = buildElementValueSerializer(namespace, value.value, value.key)
        val descriptor = mapSerialDescriptor(
            PrimitiveSerialDescriptor("key", PrimitiveKind.STRING),
            elementValueSerializer.descriptor
        )

        when (val it = value.value) {
            is String -> encodeStringElement(descriptor, index, it)
            is Int -> encodeIntElement(descriptor, index, it)
            is Long -> encodeLongElement(descriptor, index, it)
            is LocalDate -> encodeSerializableElement(descriptor, index, LocalDate.serializer(), it)
            is Instant -> encodeSerializableElement(descriptor, index, InstantStringSerializer(), it)
            is Boolean -> encodeBooleanElement(descriptor, index, it)
            is ByteArray -> encodeSerializableElement(descriptor, index, ByteArraySerializer(), it)
            else -> CborCredentialSerializer.encode(namespace, value.key, descriptor, index, this, it)
        }
    }

    private inline fun <reified T> buildElementValueSerializer(
        namespace: String,
        elementValue: T,
        elementIdentifier: String
    ) = when (elementValue) {
        is String -> String.serializer()
        is Int -> Int.serializer()
        is Long -> Long.serializer()
        is LocalDate -> LocalDate.serializer()
        is Instant -> InstantStringSerializer()
        is Boolean -> Boolean.serializer()
        is ByteArray -> ByteArraySerializer()
        is Any -> CborCredentialSerializer.lookupSerializer(namespace, elementIdentifier)
            ?: error("serializer not found for $elementIdentifier, with value $elementValue")

        else -> error("serializer not found for $elementIdentifier, with value $elementValue")
    }

    override fun deserialize(decoder: Decoder): DeviceSignedItemList {
        val entries = mutableListOf<DeviceSignedItem>()
        decoder.decodeStructure(descriptor) {
            lateinit var key: String
            var value: Any
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) {
                    break
                } else if (index % 2 == 0) {
                    key = decodeStringElement(descriptor, index)
                } else if (index % 2 == 1) {
                    value = decodeAnything(index, key)
                    entries += DeviceSignedItem(key, value)
                }
            }
        }
        return DeviceSignedItemList(entries)
    }

    private fun CompositeDecoder.decodeAnything(index: Int, elementIdentifier: String?): Any {
        if (namespace.isBlank())
            Napier.w("This decoder is not namespace-aware! Unspeakable things may happen…")

        // Tags are not read out here but skipped because `decodeElementIndex` is never called, so we cannot
        // discriminate technically, this should be a good thing though, because otherwise we'd consume more from the
        // input
        elementIdentifier?.let {
            CborCredentialSerializer.decode(descriptor, index, this, elementIdentifier, namespace)
                ?.let { return it }
                ?: Napier.v(
                    "Falling back to defaults for namespace $namespace and elementIdentifier $elementIdentifier"
                )
        }

        // These are the ones that map to different CBOR data types, the rest don't, so if it is not registered, we'll
        // lose type information. No others must be added here, as they could consume data from the underlying bytes
        runCatching { return decodeStringElement(descriptor, index) }
        runCatching { return decodeLongElement(descriptor, index) }
        runCatching { return decodeDoubleElement(descriptor, index) }
        runCatching { return decodeBooleanElement(descriptor, index) }

        throw IllegalArgumentException("Could not decode value at $index")
    }
}