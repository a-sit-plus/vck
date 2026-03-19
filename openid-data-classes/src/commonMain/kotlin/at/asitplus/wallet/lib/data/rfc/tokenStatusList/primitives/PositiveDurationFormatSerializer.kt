package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.serialization.FormatTransformingSerializerTemplate
import kotlinx.serialization.KSerializer

object PositiveDurationFormatSerializer : KSerializer<PositiveDuration> by FormatTransformingSerializerTemplate(
    descriptor = PositiveDuration.serializer().descriptor,
    jsonTransformer = PositiveDurationSecondsJsonNumberSerializer,
    cborTransformer = PositiveDurationSecondsULongSerializer
)