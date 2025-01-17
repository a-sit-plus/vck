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
            is DCQLClaimsPathPointerSegment.DCQLClaimsPathPointerNameSegment -> {
                JsonPrimitive(it.name)
            }

            is DCQLClaimsPathPointerSegment.DCQLClaimsPathPointerIndexSegment -> {
                JsonPrimitive(it.index.toLong())
            }

            is DCQLClaimsPathPointerSegment.DCQLClaimsPathPointerNullSegment -> {
                JsonNull
            }
        }
    },

    decodeAs = {
        when {
            it is JsonNull -> DCQLClaimsPathPointerSegment.DCQLClaimsPathPointerNullSegment

            it.longOrNull != null -> DCQLClaimsPathPointerSegment.DCQLClaimsPathPointerIndexSegment(
                it.long.toUInt()
            )

            else -> DCQLClaimsPathPointerSegment.DCQLClaimsPathPointerNameSegment(it.content)
        }
    }
)