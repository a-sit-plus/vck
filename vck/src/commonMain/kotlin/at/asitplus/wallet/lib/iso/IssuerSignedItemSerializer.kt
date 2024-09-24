package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.data.InstantStringSerializer
import at.asitplus.wallet.lib.iso.IssuerSignedItem.Companion.PROP_DIGEST_ID
import at.asitplus.wallet.lib.iso.IssuerSignedItem.Companion.PROP_ELEMENT_ID
import at.asitplus.wallet.lib.iso.IssuerSignedItem.Companion.PROP_ELEMENT_VALUE
import at.asitplus.wallet.lib.iso.IssuerSignedItem.Companion.PROP_RANDOM
import io.github.aakira.napier.Napier
import kotlinx.datetime.Instant
import kotlinx.datetime.LocalDate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.*

open class IssuerSignedItemSerializer(private val namespace: String) : KSerializer<IssuerSignedItem> {

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("IssuerSignedItem") {
        element(PROP_DIGEST_ID, Long.serializer().descriptor)
        element(PROP_RANDOM, ByteArraySerializer().descriptor)
        element(PROP_ELEMENT_ID, String.serializer().descriptor)
        element(PROP_ELEMENT_VALUE, String.serializer().descriptor)
    }

    override fun serialize(encoder: Encoder, value: IssuerSignedItem) {
        encoder.encodeStructure(descriptor) {
            encodeLongElement(descriptor, 0, value.digestId.toLong())
            encodeSerializableElement(descriptor, 1, ByteArraySerializer(), value.random)
            encodeStringElement(descriptor, 2, value.elementIdentifier)
            encodeAnything(value, 3)
        }
    }

    private fun CompositeEncoder.encodeAnything(value: IssuerSignedItem, index: Int) {
        val descriptor = buildClassSerialDescriptor("IssuerSignedItem") {
            element(PROP_DIGEST_ID, Long.serializer().descriptor)
            element(PROP_RANDOM, ByteArraySerializer().descriptor)
            element(PROP_ELEMENT_ID, String.serializer().descriptor)
            element(
                elementName = PROP_ELEMENT_VALUE,
                descriptor = buildElementValueSerializer(value.elementValue).descriptor,
                annotations = value.elementValue.annotations()
            )
        }

        when (val it = value.elementValue) {
            is String -> encodeStringElement(descriptor, index, it)
            is Int -> encodeIntElement(descriptor, index, it)
            is LocalDate -> encodeSerializableElement(descriptor, index, LocalDate.serializer(), it)
            is Instant -> encodeSerializableElement(descriptor, index, InstantStringSerializer(), it)
            is Boolean -> encodeBooleanElement(descriptor, index, it)
            is ByteArray -> encodeSerializableElement(descriptor, index, ByteArraySerializer(), it)
            else -> CborCredentialSerializer.encode(descriptor, index, this, it)
        }
    }

    private fun Any.annotations() =
        if (this is LocalDate || this is Instant) {
            @OptIn(ExperimentalUnsignedTypes::class)
            listOf(ValueTags(1004uL))
        } else {
            emptyList()
        }

    private inline fun <reified T> buildElementValueSerializer(element: T) = when (element) {
        is String -> String.serializer()
        is Int -> Int.serializer()
        is LocalDate -> LocalDate.serializer()
        is Instant -> InstantStringSerializer()
        is Boolean -> Boolean.serializer()
        is ByteArray -> ByteArraySerializer()
        is Any -> CborCredentialSerializer.lookupSerializer(element) ?: error("descriptor not found for $element")
        else -> error("descriptor not found for $element")
    }


    override fun deserialize(decoder: Decoder): IssuerSignedItem {
        var digestId = 0U
        lateinit var random: ByteArray
        lateinit var elementIdentifier: String
        lateinit var elementValue: Any
        decoder.decodeStructure(descriptor) {
            while (true) {
                val name = decodeStringElement(descriptor, 0)
                // Don't call decodeElementIndex, as it would check for tags. this would break decodeAnything
                val index = descriptor.getElementIndex(name)
                when (name) {
                    PROP_DIGEST_ID -> digestId = decodeLongElement(descriptor, index).toUInt()
                    PROP_RANDOM -> random = decodeSerializableElement(descriptor, index, ByteArraySerializer())
                    PROP_ELEMENT_ID -> elementIdentifier = decodeStringElement(descriptor, index)
                    PROP_ELEMENT_VALUE -> elementValue = decodeAnything(index, elementIdentifier)
                }
                if (index == 3) break
            }
        }
        return IssuerSignedItem(
            digestId = digestId,
            random = random,
            elementIdentifier = elementIdentifier,
            elementValue = elementValue
        )
    }

    private fun CompositeDecoder.decodeAnything(index: Int, elementIdentifier: String): Any {
        if (namespace.isBlank()) Napier.w { "This decoder is not namespace-aware! Unspeakable things may happen…" }

        // Tags are not read out here but skipped because `decodeElementIndex` is never called, so we cannot
        // discriminate technically, this should be a good thing though, because otherwise we'd consume more from the
        // input
        runCatching {
            CborCredentialSerializer.decode(descriptor, index, this, elementIdentifier, namespace)
                ?.let { return it }
                ?: Napier.w {
                    "Could not find a registered decoder for namespace $namespace and elementIdentifier" +
                            " $elementIdentifier. Falling back to defaults"
                }
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