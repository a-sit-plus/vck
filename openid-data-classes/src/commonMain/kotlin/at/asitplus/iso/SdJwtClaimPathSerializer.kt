package at.asitplus.iso

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Serializes the SD-JWT claim path a `DataElementIdentifier` maps to in [DocRequestInfo.dataElementIdentifierMapping]
 * as a CBOR array of path components (`[+ PathComponent]`, `PathComponent = tstr / uint / null`, WG10 N2933 v2,
 * "DeviceRequest changes"), which select claims as a claims path pointer of SD-JWT VC does.
 */
object SdJwtClaimPathSerializer : KSerializer<DCQLClaimsPathPointer> {
    private val listSerializer = ListSerializer(SdJwtClaimPathComponentSerializer)

    @OptIn(ExperimentalSerializationApi::class)
    override val descriptor: SerialDescriptor =
        SerialDescriptor("at.asitplus.iso.SdJwtClaimPath", listSerializer.descriptor)

    override fun serialize(encoder: Encoder, value: DCQLClaimsPathPointer) =
        encoder.encodeSerializableValue(listSerializer, value.segments)

    override fun deserialize(decoder: Decoder): DCQLClaimsPathPointer {
        val segments = decoder.decodeSerializableValue(listSerializer)
        if (segments.isEmpty()) throw SerializationException("An SD-JWT claim path has at least one component")
        return DCQLClaimsPathPointer(segments.toNonEmptyList())
    }
}

/** One component of a [SdJwtClaimPathSerializer] path: a text string, an unsigned integer, or `null`. */
private object SdJwtClaimPathComponentSerializer : KSerializer<DCQLClaimsPathPointerSegment> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("at.asitplus.iso.SdJwtClaimPathComponent", PrimitiveKind.STRING)

    @OptIn(ExperimentalSerializationApi::class)
    override fun serialize(encoder: Encoder, value: DCQLClaimsPathPointerSegment) = when (value) {
        is DCQLClaimsPathPointerSegment.NameSegment -> encoder.encodeString(value.name)
        is DCQLClaimsPathPointerSegment.IndexSegment -> encoder.encodeLong(value.index.toLong())
        DCQLClaimsPathPointerSegment.NullSegment -> encoder.encodeNull()
    }

    @OptIn(ExperimentalSerializationApi::class)
    override fun deserialize(decoder: Decoder): DCQLClaimsPathPointerSegment {
        if (!decoder.decodeNotNullMark()) {
            decoder.decodeNull()
            return DCQLClaimsPathPointerSegment.NullSegment
        }
        // A failed attempt does not consume the item, as for WrpStringListSerializer
        return try {
            DCQLClaimsPathPointerSegment.NameSegment(decoder.decodeString())
        } catch (_: SerializationException) {
            val index = decoder.decodeLong()
            if (index < 0 || index > UInt.MAX_VALUE.toLong())
                throw SerializationException("A component of an SD-JWT claim path is no unsigned integer")
            DCQLClaimsPathPointerSegment.IndexSegment(index.toUInt())
        }
    }
}
