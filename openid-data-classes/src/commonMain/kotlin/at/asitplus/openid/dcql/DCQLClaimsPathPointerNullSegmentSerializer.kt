package at.asitplus.openid.dcql

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonNull

object DCQLClaimsPathPointerNullSegmentSerializer : KSerializer<DCQLClaimsPathPointerSegment.DCQLClaimsPathPointerNullSegment> by TransformingSerializerTemplate<DCQLClaimsPathPointerSegment.DCQLClaimsPathPointerNullSegment, JsonNull>(
    parent = JsonNull.serializer(),
    encodeAs = {
        JsonNull
    },

    decodeAs = {
        DCQLClaimsPathPointerSegment.DCQLClaimsPathPointerNullSegment
    }
)