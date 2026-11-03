package at.asitplus.openid.dcql

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive

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

            it.isString -> DCQLClaimsPathPointerSegment.NameSegment(it.content)

            else -> it.content.toUIntOrNull()?.let { index -> DCQLClaimsPathPointerSegment.IndexSegment(index) }
                ?: throw SerializationException("Invalid segment of a claims path pointer")
        }
    }
)