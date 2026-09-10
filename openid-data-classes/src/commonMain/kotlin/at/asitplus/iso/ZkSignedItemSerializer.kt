package at.asitplus.iso

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.github.aakira.napier.Napier
import kotlinx.datetime.LocalDate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.CompositeEncoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import kotlin.time.Instant

open class ZkSignedItemSerializer(private val namespace: String) :
    KSerializer<ZkSignedItem> {

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ZkSignedItem") {
        element(ZkSignedItem.PROP_ELEMENT_ID, String.serializer().descriptor)
        element(ZkSignedItem.PROP_ELEMENT_VALUE, buildClassSerialDescriptor("AnyFallback"))
    }

    override fun serialize(encoder: Encoder, value: ZkSignedItem) {
        val elementValueSerializer = buildElementValueSerializer(namespace, value.elementValue, value.elementIdentifier)
        val dynamicDescriptor = buildClassSerialDescriptor("ZkSignedItem") {
            element(ZkSignedItem.PROP_ELEMENT_ID, String.serializer().descriptor)
            element(ZkSignedItem.PROP_ELEMENT_VALUE, elementValueSerializer.descriptor, value.elementValue.annotations())
        }

        encoder.encodeStructure(dynamicDescriptor) {
            encodeStringElement(dynamicDescriptor, 0, value.elementIdentifier)
            encodeAnything(dynamicDescriptor, value, 1)
        }
    }

    private fun CompositeEncoder.encodeAnything(dynamicDescriptor: SerialDescriptor, value: ZkSignedItem, index: Int) {
        when (val it = value.elementValue) {
            is String -> encodeStringElement(dynamicDescriptor, index, it)
            is Int -> encodeIntElement(dynamicDescriptor, index, it)
            is Long -> encodeLongElement(dynamicDescriptor, index, it)
            is LocalDate -> encodeSerializableElement(dynamicDescriptor, index, LocalDate.serializer(), it)
            is Instant -> encodeSerializableElement(dynamicDescriptor, index, InstantStringSerializer, it)
            is Boolean -> encodeBooleanElement(dynamicDescriptor, index, it)
            is ByteArray -> encodeSerializableElement(dynamicDescriptor, index, ByteArraySerializer(), it)
            else -> CborCredentialSerializer.encode(namespace, value.elementIdentifier, dynamicDescriptor, index, this, it)
        }
    }

    /**
     * Tags date time elements correctly,
     * see [RFC 8949 3.4.1](https://datatracker.ietf.org/doc/html/rfc8949#name-standard-date-time-string) for [Instant]
     * (or "date-time"), see [RFC 8943](https://datatracker.ietf.org/doc/html/rfc8943) for [LocalDate] (or "full-date")
     */
    private fun Any.annotations(): List<Annotation> = when (this) {
        is LocalDate -> listOf(ValueTags(1004uL))
        is Instant -> listOf(ValueTags(0uL))
        else -> emptyList()
    }


    override fun deserialize(decoder: Decoder): ZkSignedItem {
        var elementIdentifier: String? = null
        var elementValue: Any? = null
        decoder.decodeStructure(descriptor) {
            while (true) {
                val name = runCatching { decodeStringElement(descriptor, 0) }.getOrElse { break }
                // Don't call decodeElementIndex, as it would check for tags. this would break decodeAnything
                val index = descriptor.getElementIndex(name)
                if (index == CompositeDecoder.UNKNOWN_NAME) {
                    continue
                }

                when (name) {
                    ZkSignedItem.PROP_ELEMENT_ID -> elementIdentifier = decodeStringElement(descriptor, index)
                    ZkSignedItem.PROP_ELEMENT_VALUE -> elementValue = decodeAnything(index, elementIdentifier)

                    // TODO: Fix broken by design implementation. In non-canonicalized cbor, the order of
                    //  elementIdentifier and elementValue may vary. We can't correctly predict how the elementValue
                    //  should be deserialized. Possible solution: obor maps
                }
                if (elementValue != null && elementIdentifier != null) break
            }
        }
        return ZkSignedItem(
            elementIdentifier = requireNotNull(elementIdentifier) { "Missing elementIdentifier" },
            elementValue = requireNotNull(elementValue) { "Missing elementValue" }
        )
    }

    private fun CompositeDecoder.decodeAnything(index: Int, elementIdentifier: String?): Any {
        if (namespace.isBlank())
            Napier.w("This decoder is not namespace-aware! Unspeakable things may happen…")

        // Tags are not read out here but skipped because `decodeElementIndex` is never called, so we cannot
        // discriminate technically, this should be a good thing though, because otherwise we'd consume more from the
        // input
        elementIdentifier?.let {
            CborCredentialSerializer.decode(descriptor, index, this, it, namespace)
                ?.let { return it }
        }

        // These are the ones that map to different CBOR data types, the rest don't, so if it is not registered, we'll
        // lose type information. No others must be added here, as they could consume data from the underlying bytes
        catchingUnwrapped { return decodeStringElement(descriptor, index) }
        catchingUnwrapped { return decodeLongElement(descriptor, index) }
        catchingUnwrapped { return decodeDoubleElement(descriptor, index) }
        catchingUnwrapped { return decodeBooleanElement(descriptor, index) }

        throw IllegalArgumentException("Could not decode value at $index")
    }

    companion object {
        private fun <T> buildElementValueSerializer(
            namespace: String,
            elementValue: T,
            elementIdentifier: String
        ) = when (elementValue) {
            is String -> String.serializer()
            is Int -> Int.serializer()
            is Long -> Long.serializer()
            is LocalDate -> LocalDate.serializer()
            is Instant -> InstantStringSerializer
            is Boolean -> Boolean.serializer()
            is ByteArray -> ByteArraySerializer()
            is Any -> CborCredentialSerializer.lookupSerializer(namespace, elementIdentifier)
                ?: error("serializer not found for $elementIdentifier, with value $elementValue")

            else -> error("serializer not found for $elementIdentifier, with value $elementValue")
        }

        fun serializeElementValue(
            namespace: String,
            elementValue: Any,
            elementIdentifier: String
        ): ByteArray {
            val elementValueSerializer = buildElementValueSerializer(namespace, elementValue, elementIdentifier)
            @Suppress("UNCHECKED_CAST")
            return  coseCompliantSerializer.encodeToByteArray(elementValueSerializer as KSerializer<Any>, elementValue)
        }
    }
}

