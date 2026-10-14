package at.asitplus.etsi.relyingParty

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
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
 * Serializes a [WrpClaimPathSegment] as a string, `null`, or a non-negative integer. A WRPRC in JWT format (JSON) may
 * carry any of them. Without a generic CBOR element in kotlinx-serialization, the segments of a WRPRC in CWT format
 * can only be decoded as strings or `null`, which covers the paths of ISO mdoc claims, a namespace and an element
 * identifier (OpenID4VP 1.0, 7.2).
 */
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

    override fun deserialize(decoder: Decoder): WrpClaimPathSegment = if (decoder is JsonDecoder) {
        when (val element = decoder.decodeJsonElement()) {
            JsonNull -> WrpClaimPathSegment.AllElements
            is JsonPrimitive if element.isString -> WrpClaimPathSegment.Name(element.content)
            is JsonPrimitive if element.longOrNull?.let { it >= 0 } == true ->
                WrpClaimPathSegment.Index(element.longOrNull!!.toUInt())

            else -> throw SerializationException("Invalid segment of a claim path: $element")
        }
    } else if (decoder.decodeNotNullMark()) {
        WrpClaimPathSegment.Name(decoder.decodeString())
    } else {
        decoder.decodeNull()
        WrpClaimPathSegment.AllElements
    }
}
