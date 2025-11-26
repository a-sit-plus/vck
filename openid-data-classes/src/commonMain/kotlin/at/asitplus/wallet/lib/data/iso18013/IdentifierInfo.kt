package at.asitplus.wallet.lib.data.iso18013

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.nullable

@Serializable(with = IdentifierInfo.TransformingSerializer::class)
data class IdentifierInfo(
    val keys: Map<IdentifierInfoKey, RFU?> = emptyMap(),
) {
    object TransformingSerializer : TransformingSerializerTemplate<IdentifierInfo, Map<IdentifierInfoKey, RFU?>>(
        parent = MapSerializer(IdentifierInfoKey.Serializer, RFU.serializer().nullable),
        encodeAs = { it.keys },
        decodeAs = { IdentifierInfo(it) }
    )
}