package at.asitplus.iso

import at.asitplus.catchingUnwrapped
import at.asitplus.iso.IssuerSignedItem.Companion.PROP_DIGEST_ID
import at.asitplus.iso.IssuerSignedItem.Companion.PROP_ELEMENT_ID
import at.asitplus.iso.IssuerSignedItem.Companion.PROP_ELEMENT_VALUE
import at.asitplus.iso.IssuerSignedItem.Companion.PROP_RANDOM
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.github.aakira.napier.Napier
import kotlin.time.Instant
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
import net.orandja.obor.data.CborMap
import net.orandja.obor.data.CborText

open class IssuerSignedItemSerializer(private val namespace: String, private val elementIdentifier: String) :
    KSerializer<IssuerSignedItem> {

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
        val elementValueSerializer = buildElementValueSerializer(namespace, value.elementValue, value.elementIdentifier)
        val descriptor = buildClassSerialDescriptor("IssuerSignedItem") {
            element(PROP_DIGEST_ID, Long.serializer().descriptor)
            element(PROP_RANDOM, ByteArraySerializer().descriptor)
            element(PROP_ELEMENT_ID, String.serializer().descriptor)
            element(PROP_ELEMENT_VALUE, elementValueSerializer.descriptor, value.elementValue.annotations())
        }

        when (val it = value.elementValue) {
            is String -> encodeStringElement(descriptor, index, it)
            is Int -> encodeIntElement(descriptor, index, it)
            is Long -> encodeLongElement(descriptor, index, it)
            is Double -> encodeDoubleElement(descriptor, index, it)
            is Float -> encodeFloatElement(descriptor, index, it)
            is LocalDate -> encodeSerializableElement(descriptor, index, LocalDate.serializer(), it)
            is Instant -> encodeSerializableElement(descriptor, index, InstantStringSerializer, it)
            is Boolean -> encodeBooleanElement(descriptor, index, it)
            is ByteArray -> encodeSerializableElement(descriptor, index, ByteArraySerializer(), it)
            else -> CborCredentialSerializer.encode(namespace, value.elementIdentifier, descriptor, index, this, it)
        }
    }

    /**
     * Tags date time elements correctly,
     * see [RFC 8949 3.4.1](https://datatracker.ietf.org/doc/html/rfc8949#name-standard-date-time-string) for [Instant]
     * (or "date-time"), see [RFC 8943](https://datatracker.ietf.org/doc/html/rfc8943) for [LocalDate] (or "full-date")
     */
    @OptIn(ExperimentalUnsignedTypes::class)
    private fun Any.annotations() =
        when (this) {
            is LocalDate -> listOf(ValueTags(1004uL))
            is Instant -> listOf(ValueTags(0uL))
            else -> emptyList()
        }

    private inline fun <reified T> buildElementValueSerializer(
        namespace: String,
        elementValue: T,
        elementIdentifier: String
    ) = when (elementValue) {
        is String -> String.serializer()
        is Int -> Int.serializer()
        is Long -> Long.serializer()
        is Double -> Double.serializer()
        is Float -> Float.serializer()
        is LocalDate -> LocalDate.serializer()
        is Instant -> InstantStringSerializer
        is Boolean -> Boolean.serializer()
        is ByteArray -> ByteArraySerializer()
        is Any -> CborCredentialSerializer.lookupSerializer(namespace, elementIdentifier)
            ?: error("serializer not found for $elementIdentifier, with value $elementValue")

        else -> error("serializer not found for $elementIdentifier, with value $elementValue")
    }


    override fun deserialize(decoder: Decoder): IssuerSignedItem {
        var digestId = 0U
        var random: ByteArray? = null
        var decodedElementIdentifier: String? = elementIdentifier.takeIf { it.isNotBlank() }
        var decodedElementValue: Any? = null
        decoder.decodeStructure(descriptor) {
            while (true) {
                val name = decodeStringElement(descriptor, 0)
                // Don't call decodeElementIndex, as it would check for tags. this would break decodeAnything
                val index = descriptor.getElementIndex(name)
                when (name) {
                    PROP_DIGEST_ID -> digestId = decodeLongElement(descriptor, index).toUInt()
                    PROP_RANDOM -> random = decodeSerializableElement(descriptor, index, ByteArraySerializer())
                    PROP_ELEMENT_ID -> {
                        val elementIdInPayload = decodeStringElement(descriptor, index)
                        if (decodedElementIdentifier != null && decodedElementIdentifier != elementIdInPayload)
                            throw IllegalArgumentException("Element identifier mismatch")
                        decodedElementIdentifier = elementIdInPayload
                    }

                    PROP_ELEMENT_VALUE -> decodedElementValue = decodeAnything(index, decodedElementIdentifier)
                }
                if (random != null && decodedElementValue != null) break
            }
        }

        val resolvedElementIdentifier = decodedElementIdentifier
            ?: throw IllegalArgumentException("Missing element identifier")
        val resolvedElementValue = decodedElementValue
            ?: throw IllegalArgumentException("Missing element value")

        return IssuerSignedItem(
            digestId = digestId,
            random = random!!,
            elementIdentifier = resolvedElementIdentifier,
            elementValue = resolvedElementValue,
        )
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
        }

        catchingUnwrapped {
            return decodeGenericElementValue(decodeSerializableElement(descriptor, index, ByteArraySerializer()))
        }
        catchingUnwrapped { return decodeStringElement(descriptor, index) }

        throw IllegalArgumentException("Could not decode value at $index")
    }

    internal fun deserializeFromOborMap(item: CborMap): IssuerSignedItem = item.toIssuerSignedItem()

    private fun CborMap.toIssuerSignedItem(): IssuerSignedItem {
        val digestId = coseCompliantSerializer.decodeFromByteArray(
            Long.serializer(),
            first { (it.key as CborText).value == PROP_DIGEST_ID }.value.cbor
        ).toUInt()
        val random = coseCompliantSerializer.decodeFromByteArray(
            ByteArraySerializer(),
            first { (it.key as CborText).value == PROP_RANDOM }.value.cbor
        )
        val elementId = (first { (it.key as CborText).value == PROP_ELEMENT_ID }.value as CborText)
            .value
        if (elementIdentifier.isNotBlank() && elementIdentifier != elementId) {
            throw IllegalArgumentException("Element identifier mismatch")
        }

        val elementValueContainer = first { (it.key as CborText).value == PROP_ELEMENT_VALUE }.value
        val elementValue = CborCredentialSerializer.lookupSerializer(namespace, elementId)?.let {
            coseCompliantSerializer.decodeFromByteArray(it, elementValueContainer.cbor)
        } ?: decodeGenericElementValue(elementValueContainer.cbor)

        return IssuerSignedItem(digestId, random, elementId, elementValue)
    }

    private fun decodeGenericElementValue(bytes: ByteArray): Any {
        runCatching { return coseCompliantSerializer.decodeFromByteArray(LocalDate.serializer(), bytes) }
        runCatching { return coseCompliantSerializer.decodeFromByteArray(InstantStringSerializer, bytes) }
        runCatching { return coseCompliantSerializer.decodeFromByteArray(String.serializer(), bytes) }
        runCatching { return coseCompliantSerializer.decodeFromByteArray(Long.serializer(), bytes) }
        runCatching { return coseCompliantSerializer.decodeFromByteArray(Double.serializer(), bytes) }
        runCatching { return coseCompliantSerializer.decodeFromByteArray(Boolean.serializer(), bytes) }
        runCatching { return coseCompliantSerializer.decodeFromByteArray(ByteArraySerializer(), bytes) }
        return bytes
    }

}
