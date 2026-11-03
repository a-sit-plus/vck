package at.asitplus.etsi.relyingParty

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonPrimitive

/**
 * Serializes a non-empty list of strings as an array, and decodes an array or a single string, in JSON and CBOR.
 * ETSI TS 119 475 V1.2.1 allows several values for these WRPRC fields in the register (Annex B), but shows them as
 * strings in its example (Annex C), and Table 7 defines no JSON type for them.
 *
 * CBOR decoding tries a text string before an array, relying on kotlinx-serialization (since 1.10.0) checking the
 * major type before consuming input; see [WrpClaimPathSegmentSerializer].
 */
@OptIn(ExperimentalSerializationApi::class)
internal object WrpStringListSerializer : KSerializer<List<String>> {
    private val listSerializer = ListSerializer(String.serializer())

    override val descriptor: SerialDescriptor =
        SerialDescriptor("at.asitplus.etsi.relyingParty.WrpStringList", listSerializer.descriptor)

    override fun serialize(encoder: Encoder, value: List<String>) =
        encoder.encodeSerializableValue(listSerializer, value.requireNotEmpty())

    override fun deserialize(decoder: Decoder): List<String> = when (decoder) {
        is JsonDecoder -> when (val element = decoder.decodeJsonElement()) {
            is JsonPrimitive if element.isString -> listOf(element.content)
            is JsonArray -> decoder.json.decodeFromJsonElement(listSerializer, element)
            else -> throw SerializationException("Expected a string or an array of strings: $element")
        }

        is CborDecoder -> try {
            listOf(decoder.decodeString())
        } catch (_: SerializationException) {
            decoder.decodeSerializableValue(listSerializer)
        }

        else -> decoder.decodeSerializableValue(listSerializer)
    }.requireNotEmpty()

    // A field is absent if the register provides no value for it, never empty (Annex B)
    private fun List<String>.requireNotEmpty() =
        also { if (isEmpty()) throw SerializationException("Expected at least one string") }
}
