package at.asitplus.iso


import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SealedSerializationApi
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeCollection

open class ZkSignedListSerializer(private val namespace: String) : KSerializer<ZkSignedList> {

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
        override fun getElementAnnotations(index: Int): List<Annotation> = emptyList()

        @ExperimentalSerializationApi
        override fun getElementDescriptor(index: Int): SerialDescriptor =
            ZkSignedItemSerializer(namespace).descriptor

        @ExperimentalSerializationApi
        override fun getElementIndex(name: String): Int = name.toInt()

        @ExperimentalSerializationApi
        override fun getElementName(index: Int): String = index.toString()

        @ExperimentalSerializationApi
        override fun isElementOptional(index: Int): Boolean = false
    }

    override fun serialize(encoder: Encoder, value: ZkSignedList) {
        var index = 0
        encoder.encodeCollection(descriptor, value.entries.size) {
            value.entries.forEach { item ->
                encodeSerializableElement(
                    descriptor,
                    index++,
                    ZkSignedItemSerializer(namespace),
                    item
                )
            }
        }
    }

    override fun deserialize(decoder: Decoder): ZkSignedList {
        val entries = mutableListOf<ZkSignedItem>()
        decoder.decodeStructure(descriptor) {
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                val item = decodeSerializableElement(
                    descriptor,
                    index,
                    ZkSignedItemSerializer(namespace)
                )
                entries += item
            }
        }
        return ZkSignedList(entries)
    }
}