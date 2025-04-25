package at.asitplus.openid

import at.asitplus.openid.dcql.DCQLQuery
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*


object BackwardsCompatibleDCQLQueryTransformingSerializer : KSerializer<DCQLQuery> by TransformingSerializerTemplate<DCQLQuery, JsonElement>(
    parent = JsonElement.serializer(),
    encodeAs = { value, encoder ->
        encoder as JsonEncoder
        encoder.json.encodeToJsonElement(value)
    },
    decodeAs = { jsonElement, decoder ->
        decoder as JsonDecoder
        val indermediate = when(jsonElement) {
            is JsonPrimitive -> decoder.json.decodeFromString<JsonElement>(jsonElement.content)
            else -> jsonElement
        }
        decoder.json.decodeFromJsonElement<DCQLQuery>(indermediate)
    },
)


private sealed class TemplateSerializer<T>(serialName: String = "") : KSerializer<T> {
    protected val realSerialName =
        serialName.ifEmpty { this::class.simpleName
            ?: throw IllegalArgumentException("Anonymous classes must specify a serialName explicitly") }
}

private open class TransformingSerializerTemplate<ValueT, EncodedT>
    (private val parent: KSerializer<EncodedT>, private val encodeAs: (ValueT, Encoder)->EncodedT,
     private val decodeAs: (EncodedT, Decoder)->ValueT, serialName: String = "")
    : TemplateSerializer<ValueT>(serialName) {

    override val descriptor: SerialDescriptor =
        when (val kind = parent.descriptor.kind) {
            is PrimitiveKind -> PrimitiveSerialDescriptor(realSerialName, kind)
            else -> SerialDescriptor(realSerialName, parent.descriptor)
        }

    override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: ValueT) {
        val v = try { encodeAs(value, encoder) }
        catch (x: Throwable) { throw SerializationException("Encoding failed", x) }
        encoder.encodeSerializableValue(parent, v)
    }

    override fun deserialize(decoder: Decoder): ValueT {
        val v = decoder.decodeSerializableValue(parent)
        try { return decodeAs(v, decoder) }
        catch (x: Throwable) { throw SerializationException("Decoding failed", x) }
    }
}