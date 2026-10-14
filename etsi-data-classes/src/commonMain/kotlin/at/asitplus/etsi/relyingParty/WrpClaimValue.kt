package at.asitplus.etsi.relyingParty

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull
import kotlin.jvm.JvmInline

/**
 * ETSI TS 119 475 V1.2.1 B.2.10 expected claim value: a string, an integer or a boolean.
 */
@Serializable(with = WrpClaimValueSerializer::class)
sealed interface WrpClaimValue {
    @JvmInline
    value class StringValue(val string: String) : WrpClaimValue

    @JvmInline
    value class IntegerValue(val long: Long) : WrpClaimValue

    @JvmInline
    value class BooleanValue(val boolean: Boolean) : WrpClaimValue
}

/**
 * Serializes [WrpClaimValue] for JSON (JWT WRPRC) and CBOR (CWT WRPRC).
 *
 * For CBOR, decoding tries a text string, then a boolean, then an integer, see [WrpClaimPathSegmentSerializer].
 */
@OptIn(ExperimentalSerializationApi::class)
object WrpClaimValueSerializer : KSerializer<WrpClaimValue> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("at.asitplus.etsi.relyingParty.WrpClaimValue", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: WrpClaimValue) = when (value) {
        is WrpClaimValue.StringValue -> encoder.encodeString(value.string)
        is WrpClaimValue.IntegerValue -> encoder.encodeLong(value.long)
        is WrpClaimValue.BooleanValue -> encoder.encodeBoolean(value.boolean)
    }

    override fun deserialize(decoder: Decoder): WrpClaimValue = when (decoder) {
        is JsonDecoder -> decodeJson(decoder)
        is CborDecoder -> decodeCbor(decoder)
        else -> throw SerializationException("Unsupported format for WrpClaimValue: ${decoder::class}")
    }

    private fun decodeJson(decoder: JsonDecoder): WrpClaimValue {
        val element = decoder.decodeJsonElement()
        if (element !is JsonPrimitive || element is JsonNull)
            throw SerializationException("Invalid claim value: $element")
        if (element.isString) return WrpClaimValue.StringValue(element.content)
        element.booleanOrNull?.let { return WrpClaimValue.BooleanValue(it) }
        element.longOrNull?.let { return WrpClaimValue.IntegerValue(it) }
        throw SerializationException("Invalid claim value: $element")
    }

    private fun decodeCbor(decoder: CborDecoder): WrpClaimValue = try {
        WrpClaimValue.StringValue(decoder.decodeString())
    } catch (_: SerializationException) {
        try {
            WrpClaimValue.BooleanValue(decoder.decodeBoolean())
        } catch (_: SerializationException) {
            WrpClaimValue.IntegerValue(decoder.decodeLong())
        }
    }
}
