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
import kotlin.jvm.JvmInline

/**
 * Single segment of a [WrpClaimPath], encoded as a string, a non-negative integer or `null`.
 *
 * Segment types as defined by the claims path pointer of OpenID4VP 1.0 section 7, see [WrpClaimPath].
 */
@Serializable(with = WrpClaimPathSegmentSerializer::class)
sealed interface WrpClaimPathSegment {

    /** Selects the key [name] of an object. */
    @JvmInline
    value class NameSegment(val name: String) : WrpClaimPathSegment

    /** Selects the element at [index] of an array. */
    @JvmInline
    value class IndexSegment(val index: UInt) : WrpClaimPathSegment

    /** Selects all elements of an array, encoded as `null`. */
    data object WildcardSegment : WrpClaimPathSegment
}

/**
 * Serializes [WrpClaimPathSegment] for JSON (JWT WRPRC) and CBOR (CWT WRPRC).
 *
 * For CBOR there is no way to inspect the type of the next item, so decoding tries a text string first and falls back
 * to an integer. This relies on the CBOR parser of kotlinx-serialization (since 1.10.0) checking the major type before
 * consuming input (same approach as the `x5chain` handling in Signum's `CoseHeaderSerializer`).
 *
 * Limitation: kotlinx-serialization CBOR reads an empty map (`0xa0`) as `null`, so `[{}]` decodes as a
 * [WrpClaimPathSegment.WildcardSegment] instead of being rejected. Non-empty maps and arrays are rejected.
 */
@OptIn(ExperimentalSerializationApi::class)
object WrpClaimPathSegmentSerializer : KSerializer<WrpClaimPathSegment> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("at.asitplus.etsi.relyingParty.WrpClaimPathSegment", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: WrpClaimPathSegment) = when (value) {
        is WrpClaimPathSegment.NameSegment -> encoder.encodeString(value.name)
        is WrpClaimPathSegment.IndexSegment -> encoder.encodeLong(value.index.toLong())
        WrpClaimPathSegment.WildcardSegment -> encoder.encodeNull()
    }

    override fun deserialize(decoder: Decoder): WrpClaimPathSegment = when (decoder) {
        is JsonDecoder -> decodeJson(decoder)
        is CborDecoder -> decodeCbor(decoder)
        else -> throw SerializationException("Unsupported format for WrpClaimPathSegment: ${decoder::class}")
    }

    private fun decodeJson(decoder: JsonDecoder): WrpClaimPathSegment =
        when (val element = decoder.decodeJsonElement()) {
            JsonNull -> WrpClaimPathSegment.WildcardSegment
            is JsonPrimitive -> when {
                element.isString -> WrpClaimPathSegment.NameSegment(element.content)
                else -> element.content.toUIntOrNull()?.let { WrpClaimPathSegment.IndexSegment(it) }
                    ?: throw SerializationException("Invalid claim path segment: $element")
            }

            else -> throw SerializationException("Invalid claim path segment: $element")
        }

    private fun decodeCbor(decoder: CborDecoder): WrpClaimPathSegment {
        if (!decoder.decodeNotNullMark()) {
            decoder.decodeNull()
            return WrpClaimPathSegment.WildcardSegment
        }
        return try {
            WrpClaimPathSegment.NameSegment(decoder.decodeString())
        } catch (_: SerializationException) {
            val index = decoder.decodeLong()
            if (index < 0 || index > UInt.MAX_VALUE.toLong())
                throw SerializationException("Invalid claim path segment: $index")
            WrpClaimPathSegment.IndexSegment(index.toUInt())
        }
    }
}
