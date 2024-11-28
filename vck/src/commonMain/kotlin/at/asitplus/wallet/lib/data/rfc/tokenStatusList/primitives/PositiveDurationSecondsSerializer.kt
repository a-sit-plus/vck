package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.builtins.serializer
import kotlin.time.DurationUnit
import kotlin.time.toDuration

object PositiveDurationSecondsSerializer : TransformingSerializerTemplate<PositiveDuration, Double>(
    parent = Double.serializer(),
    decodeAs = {
        PositiveDuration(
            it.toDuration(DurationUnit.SECONDS)
        )
    },
    encodeAs = {
        it.value.inWholeNanoseconds.toDouble() / 1000000000
    }
)