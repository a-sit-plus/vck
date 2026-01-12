package at.asitplus.iso

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.listSerialDescriptor
import kotlinx.serialization.descriptors.mapSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import kotlin.collections.plusAssign

/**
 * Serializes [ItemsRequestList.entries] as an "inline map",
 * having [SingleItemsRequest.dataElementIdentifier] as the map key and [SingleItemsRequest.intentToRetain] as the map value,
 * for the map represented by [ItemsRequestList].
 */
object ItemsRequestListSerializer : KSerializer<ItemsRequestList> {

    override val descriptor: SerialDescriptor = mapSerialDescriptor(
        keyDescriptor = PrimitiveSerialDescriptor("key", PrimitiveKind.INT),
        valueDescriptor = listSerialDescriptor<Byte>(),
    )

    override fun serialize(encoder: Encoder, value: ItemsRequestList) {
        encoder.encodeStructure(descriptor) {
            var index = 0
            value.entries.forEach {
                this.encodeStringElement(descriptor, index++, it.dataElementIdentifier)
                this.encodeBooleanElement(descriptor, index++, it.intentToRetain)
            }
        }
    }

    override fun deserialize(decoder: Decoder): ItemsRequestList {
        val entries = mutableListOf<SingleItemsRequest>()
        decoder.decodeStructure(descriptor) {
            lateinit var key: String
            var value: Boolean
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) {
                    break
                } else if (index % 2 == 0) {
                    key = decodeStringElement(descriptor, index)
                } else if (index % 2 == 1) {
                    value = decodeBooleanElement(descriptor, index)
                    entries += SingleItemsRequest(key, value)
                }
            }
        }
        return ItemsRequestList(entries)
    }
}