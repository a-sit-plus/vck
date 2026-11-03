package at.asitplus.etsi.relyingParty

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlin.jvm.JvmInline

/**
 * A segment of the path pointer of a [WrpClaim] (ETSI TS 119 475 V1.2.1, B.2.10), which follows the claims path
 * pointer of OpenID4VP (OpenID4VP 1.0, 7): a string selects the key of an object, `null` all elements of an array,
 * and a non-negative integer the element of an array at that index.
 */
@Serializable(with = WrpClaimPathSegmentSerializer::class)
sealed interface WrpClaimPathSegment {

    /** Selects the claim [name] of an object. */
    @JvmInline
    value class Name(val name: String) : WrpClaimPathSegment

    /** Selects the element at [index] of an array. */
    @JvmInline
    value class Index(val index: UInt) : WrpClaimPathSegment

    /** Selects all elements of an array, serialized as `null`. */
    data object AllElements : WrpClaimPathSegment
}

/**
 * Encodes names, indices and wildcards as strings, non-negative integers and `null` in JSON and CBOR.
 * CBOR decoding tries text before integer, relying on kotlinx-serialization (since 1.10.0) checking the
 * major type before consuming input, as Signum's CoseHeaderSerializer does for x5chain.
 *
 * Limitation: kotlinx-serialization CBOR treats an empty map as `null`, so it also decodes as [WrpClaimPathSegment.AllElements].
 */
@OptIn(ExperimentalSerializationApi::class)
object WrpClaimPathSegmentSerializer : KSerializer<WrpClaimPathSegment> {
    override val descriptor =
        PrimitiveSerialDescriptor("at.asitplus.etsi.relyingParty.WrpClaimPathSegment", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: WrpClaimPathSegment) {
        when (value) {
            is WrpClaimPathSegment.Name -> encoder.encodeString(value.name)
            is WrpClaimPathSegment.Index -> encoder.encodeLong(value.index.toLong())
            WrpClaimPathSegment.AllElements -> encoder.encodeNull()
        }
    }

    override fun deserialize(decoder: Decoder): WrpClaimPathSegment = when (decoder) {
        is JsonDecoder -> when (val element = decoder.decodeJsonElement()) {
            JsonNull -> WrpClaimPathSegment.AllElements
            is JsonPrimitive if element.isString -> WrpClaimPathSegment.Name(element.content)
            is JsonPrimitive -> element.content.toUIntOrNull()?.let { WrpClaimPathSegment.Index(it) }
                ?: throw SerializationException("Invalid segment of a claim path")
            else -> throw SerializationException("Invalid segment of a claim path")
        }

        is CborDecoder -> if (!decoder.decodeNotNullMark()) {
            decoder.decodeNull()
            WrpClaimPathSegment.AllElements
        } else {
            try {
                WrpClaimPathSegment.Name(decoder.decodeString())
            } catch (_: SerializationException) {
                val index = decoder.decodeLong()
                if (index < 0 || index > UInt.MAX_VALUE.toLong())
                    throw SerializationException("Invalid index of a claim path")
                WrpClaimPathSegment.Index(index.toUInt())
            }
        }

        else -> throw SerializationException("Unsupported format for WrpClaimPathSegment")
    }
}
