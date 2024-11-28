package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.serialization.FormatTransformingSerializerTemplate
import kotlinx.serialization.KSerializer

object TimeToLiveSerializer : KSerializer<TimeToLive> by FormatTransformingSerializerTemplate(
    fallbackTransformer = TimeToLiveCborSerializer,
    jsonTransformer = TransformingSerializerTemplate(
        parent = JwtTimeToLive.serializer(),
        encodeAs = {
            JwtTimeToLive(it)
        },
        decodeAs = {
            it
        },
    ),
    cborTransformer = TimeToLiveCborSerializer,
)

private object TimeToLiveCborSerializer : TransformingSerializerTemplate<TimeToLive, CwtTimeToLive>(
    parent = CwtTimeToLive.serializer(),
    encodeAs = {
        CwtTimeToLive.fromTimeToLive(it)
    },
    decodeAs = {
        it
    },
)