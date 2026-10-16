package at.asitplus.etsi.relyingParty

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonObject

/**
 * Serializes `srv_description` of a [WrpPayload] as an array of arrays of [WrpLangString]s (ETSI TS 119 475 V1.2.1,
 * B.2.1, Annex C). Also decodes a single array of [WrpLangString]s, which Table 7 does not rule out, as one array
 * of localized descriptions.
 *
 * CBOR decoding tries each element as an array before an object, relying on kotlinx-serialization (since 1.10.0)
 * checking the major type before consuming input; see [WrpClaimPathSegmentSerializer].
 */
@OptIn(ExperimentalSerializationApi::class)
internal object WrpServiceDescriptionsSerializer : KSerializer<List<List<WrpLangString>>> {
    private val localizedSerializer = ListSerializer(WrpLangString.serializer())
    private val nestedSerializer = ListSerializer(localizedSerializer)

    override val descriptor: SerialDescriptor =
        SerialDescriptor("at.asitplus.etsi.relyingParty.WrpServiceDescriptions", nestedSerializer.descriptor)

    override fun serialize(encoder: Encoder, value: List<List<WrpLangString>>) =
        encoder.encodeSerializableValue(nestedSerializer, value)

    override fun deserialize(decoder: Decoder): List<List<WrpLangString>> = when (decoder) {
        is JsonDecoder -> {
            val element = decoder.decodeJsonElement()
            val nested = if (element is JsonArray && element.isNotEmpty() && element.all { it is JsonObject })
                JsonArray(listOf(element))
            else element
            decoder.json.decodeFromJsonElement(nestedSerializer, nested)
        }

        is CborDecoder -> decoder.decodeStructure(descriptor) {
            val localized = mutableListOf<List<WrpLangString>>()
            val single = mutableListOf<WrpLangString>()
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                try {
                    localized += decodeSerializableElement(descriptor, index, localizedSerializer)
                } catch (_: SerializationException) {
                    single += decodeSerializableElement(descriptor, index, WrpLangString.serializer())
                }
            }
            if (localized.isNotEmpty() && single.isNotEmpty())
                throw SerializationException("Expected either arrays or objects in srv_description, not both")
            if (single.isNotEmpty()) listOf(single) else localized
        }

        else -> decoder.decodeSerializableValue(nestedSerializer)
    }
}
