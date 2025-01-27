package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer

object DCQLClaimsPathPointerInlineSerializer : KSerializer<DCQLClaimsPathPointer> by TransformingSerializerTemplate<DCQLClaimsPathPointer, List<DCQLClaimsPathPointerSegment>>(
    parent = ListSerializer(DCQLClaimsPathPointerSegment.serializer()),
    encodeAs = {
        it.segments
    },
    decodeAs = {
        DCQLClaimsPathPointer(it.toNonEmptyList())
    }
)