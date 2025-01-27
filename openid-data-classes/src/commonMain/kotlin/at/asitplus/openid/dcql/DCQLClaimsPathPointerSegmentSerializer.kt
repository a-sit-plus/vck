package at.asitplus.openid.dcql

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.longOrNull

object DCQLClaimsPathPointerSegmentSerializer : KSerializer<DCQLClaimsPathPointerSegment> by TransformingSerializerTemplate<DCQLClaimsPathPointerSegment, JsonPrimitive>(
    parent = JsonPrimitive.serializer(),
    encodeAs = {
        when (it) {
            is DCQLClaimsPathPointerSegment.NameSegment -> JsonPrimitive(it.name)
            is DCQLClaimsPathPointerSegment.IndexSegment -> JsonPrimitive(it.index.toLong())
            is DCQLClaimsPathPointerSegment.NullSegment -> JsonNull
        }
    },

    decodeAs = {
        when {
            it is JsonNull -> DCQLClaimsPathPointerSegment.NullSegment

            it.longOrNull != null -> DCQLClaimsPathPointerSegment.IndexSegment(it.long.toUInt())

            else -> DCQLClaimsPathPointerSegment.NameSegment(it.content)
        }
    }
)