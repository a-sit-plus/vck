package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SealedSerializationApi
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.encoding.*
import net.orandja.obor.codec.Cbor
import net.orandja.obor.data.CborMap
import net.orandja.obor.data.CborObject
import net.orandja.obor.data.CborText

/**
 * Serializes [IssuerSignedList.entries] as an "inline list",
 * having serialized instances of [IssuerSignedItem] as the values.
 */
open class IssuerSignedListSerializer(private val namespace: String) : KSerializer<IssuerSignedList> {

    @OptIn(SealedSerializationApi::class)
    override val descriptor: SerialDescriptor = object : SerialDescriptor {
        @ExperimentalSerializationApi
        override val elementsCount: Int = 1

        @ExperimentalSerializationApi
        override val kind: SerialKind = StructureKind.LIST

        @ExperimentalSerializationApi
        override val serialName: String = "kotlin.collections.ArrayList"

        @ExperimentalSerializationApi
        @OptIn(ExperimentalUnsignedTypes::class)
        override fun getElementAnnotations(index: Int): List<Annotation> = listOf(ValueTags(24U))

        @ExperimentalSerializationApi
        override fun getElementDescriptor(index: Int): SerialDescriptor = Byte.serializer().descriptor

        @ExperimentalSerializationApi
        override fun getElementIndex(name: String): Int = name.toInt()

        @ExperimentalSerializationApi
        override fun getElementName(index: Int): String = index.toString()

        @ExperimentalSerializationApi
        override fun isElementOptional(index: Int): Boolean = false
    }


    override fun serialize(encoder: Encoder, value: IssuerSignedList) {
        var index = 0
        encoder.encodeCollection(descriptor, value.entries.size) {
            value.entries.forEach {
                encodeSerializableElement(descriptor, index++, ByteArraySerializer(), it.value.serialize(namespace))
            }
        }
    }

    private fun IssuerSignedItem.serialize(namespace: String): ByteArray =
        coseCompliantSerializer.encodeToByteArray(IssuerSignedItemSerializer(namespace, elementIdentifier), this)

    override fun deserialize(decoder: Decoder): IssuerSignedList {
        val entries = mutableListOf<ByteStringWrapper<IssuerSignedItem>>()
        decoder.decodeStructure(descriptor) {
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) {
                    break
                }
                val readBytes = decoder.decodeSerializableValue(ByteArraySerializer())
                val item = Cbor.decodeFromByteArray<CborObject>(readBytes) as CborMap
                val elementId = ((item.first { (it.key as CborText).value == IssuerSignedItem.PROP_ELEMENT_ID }).value as CborText).value
                entries += ByteStringWrapper(
                    item.toIssuerSignedItem(elementId),
                    item.cbor
                )
            }
        }
        return IssuerSignedList(entries)
    }

    private fun CborMap.toIssuerSignedItem(elementId: String): IssuerSignedItem {
        val digestId = coseCompliantSerializer.decodeFromByteArray(
            Long.serializer(),
            first { (it.key as CborText).value == IssuerSignedItem.PROP_DIGEST_ID }.value.cbor
        ).toUInt()
        val random = coseCompliantSerializer.decodeFromByteArray(
            ByteArraySerializer(),
            first { (it.key as CborText).value == IssuerSignedItem.PROP_RANDOM }.value.cbor
        )
        val elementValueContainer = first { (it.key as CborText).value == IssuerSignedItem.PROP_ELEMENT_VALUE }.value

        val elementValue = CborCredentialSerializer.lookupSerializer(namespace, elementId)?.let {
            coseCompliantSerializer.decodeFromByteArray(it, elementValueContainer.cbor) as Any
        } ?: decodeGenericElementValue(elementValueContainer)

        return IssuerSignedItem(digestId, random, elementId, elementValue)
    }

    private fun decodeGenericElementValue(value: CborObject): Any {
        runCatching { return coseCompliantSerializer.decodeFromByteArray(String.serializer(), value.cbor) }
        runCatching { return coseCompliantSerializer.decodeFromByteArray(Long.serializer(), value.cbor) }
        runCatching { return coseCompliantSerializer.decodeFromByteArray(Double.serializer(), value.cbor) }
        runCatching { return coseCompliantSerializer.decodeFromByteArray(Boolean.serializer(), value.cbor) }
        runCatching { return coseCompliantSerializer.decodeFromByteArray(ByteArraySerializer(), value.cbor) }
        return value
    }
}
