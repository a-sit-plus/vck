package at.asitplus.etsi.relyingParty

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer

/**
 * ETSI TS 119 475 V1.2.1 B.2.10 claim path: a non-empty array of strings (object keys), non-negative integers
 * (array indices) and `null` (all array elements).
 *
 * B.2.10 defines the path as a path pointer and refers to OpenID4VP 1.0 for guidance, whose claims path pointer
 * (section 7) defines these segments. The Annex C example and ETSI TS 119 472-2 V1.3.1 only use object keys.
 * Index and wildcard segments do not authorize a request yet.
 *
 * In CBOR, an empty map in place of a segment (`[{}]`) decodes as [WrpClaimPathSegment.WildcardSegment], see
 * [WrpClaimPathSegmentSerializer].
 *
 * Use [WrpClaimPathSegment.NameSegment] for keys, even if they look numeric: `["age_equal_or_over", "18"]` addresses the
 * key `18`, whereas `["nationalities", 0]` addresses the first array element.
 */
@Serializable(with = WrpClaimPathSerializer::class)
data class WrpClaimPath(
    val segments: List<WrpClaimPathSegment>,
) {
    init {
        require(segments.isNotEmpty()) { "Claim path must not be empty" }
    }

    /** Path consisting of object keys only, e.g. `WrpClaimPath("org.iso.18013.5.1", "given_name")`. */
    constructor(vararg names: String) : this(names.map { WrpClaimPathSegment.NameSegment(it) })

    override fun toString() = "WrpClaimPath($segments)"
}

object WrpClaimPathSerializer : KSerializer<WrpClaimPath> by TransformingSerializerTemplate(
    parent = ListSerializer(WrpClaimPathSegment.serializer()),
    encodeAs = { it.segments },
    decodeAs = {
        if (it.isEmpty()) throw SerializationException("Claim path must not be empty")
        WrpClaimPath(it)
    },
    serialName = "at.asitplus.etsi.relyingParty.WrpClaimPath",
)
