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
 * Serializes `srv_description` of a [WrpPayload] as an array of [WrpLangString]s, the localized versions of the
 * description of the one service a WRPRC is issued for: a WRPRC is issued for each combination of intended use and
 * service (ARF Annex 2, RPRC_09). Also decodes an array of arrays of [WrpLangString]s, as ETSI TS 119 475 V1.2.1
 * describes it (B.2.1, Annex C), into the [WrpLangString]s of all its arrays.
 *
 * CBOR decoding tries each element as an array before an object, relying on kotlinx-serialization (since 1.10.0)
 * checking the major type before consuming input; see [WrpClaimPathSegmentSerializer].
 */
@OptIn(ExperimentalSerializationApi::class)
internal object WrpServiceDescriptionSerializer : KSerializer<List<WrpLangString>> {
    private val localizedSerializer = ListSerializer(WrpLangString.serializer())
    private val nestedSerializer = ListSerializer(localizedSerializer)

    override val descriptor: SerialDescriptor =
        SerialDescriptor("at.asitplus.etsi.relyingParty.WrpServiceDescription", localizedSerializer.descriptor)

    override fun serialize(encoder: Encoder, value: List<WrpLangString>) =
        encoder.encodeSerializableValue(localizedSerializer, value)

    override fun deserialize(decoder: Decoder): List<WrpLangString> = when (decoder) {
        is JsonDecoder -> when (val element = decoder.decodeJsonElement()) {
            is JsonArray if element.all { it is JsonArray } ->
                decoder.json.decodeFromJsonElement(nestedSerializer, element).flatten()

            is JsonArray if element.all { it is JsonObject } ->
                decoder.json.decodeFromJsonElement(localizedSerializer, element)

            else -> throw SerializationException("Expected either arrays or objects in srv_description: $element")
        }

        is CborDecoder -> decoder.decodeStructure(descriptor) {
            val nested = mutableListOf<WrpLangString>()
            val flat = mutableListOf<WrpLangString>()
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                try {
                    nested += decodeSerializableElement(descriptor, index, localizedSerializer)
                } catch (_: SerializationException) {
                    flat += decodeSerializableElement(descriptor, index, WrpLangString.serializer())
                }
            }
            if (nested.isNotEmpty() && flat.isNotEmpty())
                throw SerializationException("Expected either arrays or objects in srv_description, not both")
            nested + flat
        }

        else -> decoder.decodeSerializableValue(localizedSerializer)
    }
}
