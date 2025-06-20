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
                val elementIdItem = item.first { (it.key as CborText).value == IssuerSignedItem.PROP_ELEMENT_ID }
                val elementId = (elementIdItem.value as CborText).value
                entries += ByteStringWrapper(
                    coseCompliantSerializer.decodeFromByteArray(IssuerSignedItemSerializer(namespace, elementId), item.cbor),
                    item.cbor
                )
            }
        }
        return IssuerSignedList(entries)
    }
}