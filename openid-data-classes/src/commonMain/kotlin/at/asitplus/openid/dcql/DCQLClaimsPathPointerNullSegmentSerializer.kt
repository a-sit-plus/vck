package at.asitplus.openid.dcql

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonNull

object DCQLClaimsPathPointerNullSegmentSerializer : KSerializer<DCQLClaimsPathPointerSegment.NullSegment> by TransformingSerializerTemplate<DCQLClaimsPathPointerSegment.NullSegment, JsonNull>(
    parent = JsonNull.serializer(),
    encodeAs = {
        JsonNull
    },

    decodeAs = {
        DCQLClaimsPathPointerSegment.NullSegment
    }
)