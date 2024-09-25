package at.asitplus.wallet.lib.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.encoding.*

/**
 * Serializes [IssuerSignedList.entries] as an "inline list",
 * having serialized instances of [IssuerSignedItem] as the values.
 */
open class IssuerSignedListSerializer(private val namespace: String) : KSerializer<IssuerSignedList> {

    override val descriptor: SerialDescriptor = object : SerialDescriptor {
        @ExperimentalSerializationApi
        override val elementsCount: Int = 1

        @ExperimentalSerializationApi
        override val kind: SerialKind = StructureKind.LIST

        @ExperimentalSerializationApi
        override val serialName: String = "kotlin.collections.ArrayList"

        @ExperimentalSerializationApi
        override fun getElementAnnotations(index: Int): List<Annotation> {
            @OptIn(ExperimentalUnsignedTypes::class)
            return listOf(ValueTags(24U))
        }

        @ExperimentalSerializationApi
        override fun getElementDescriptor(index: Int): SerialDescriptor {
            return Byte.serializer().descriptor
        }

        @ExperimentalSerializationApi
        override fun getElementIndex(name: String): Int {
            return name.toInt()
        }

        @ExperimentalSerializationApi
        override fun getElementName(index: Int): String {
            return index.toString()
        }

        @ExperimentalSerializationApi
        override fun isElementOptional(index: Int): Boolean {
            return false
        }
    }


    override fun serialize(encoder: Encoder, value: IssuerSignedList) {
        var index = 0
        encoder.encodeCollection(descriptor, value.entries.size) {
            value.entries.forEach {
                encodeSerializableElement(descriptor, index++, ByteArraySerializer(), it.value.serialize(namespace))
            }
        }
    }

    override fun deserialize(decoder: Decoder): IssuerSignedList {
        val entries = mutableListOf<ByteStringWrapper<IssuerSignedItem>>()
        decoder.decodeStructure(descriptor) {
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) {
                    break
                }
                val readBytes = decoder.decodeSerializableValue(ByteArraySerializer())
                val issuerSignedItem = IssuerSignedItem.deserialize(readBytes, namespace).getOrThrow()
                entries += ByteStringWrapper(issuerSignedItem, readBytes)
            }
        }
        return IssuerSignedList(entries)
    }
}