package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.builtins.serializer
import kotlin.time.DurationUnit
import kotlin.time.toDuration

object PositiveDurationSecondsULongSerializer : TransformingSerializerTemplate<PositiveDuration, ULong>(
    parent = ULong.serializer(),
    encodeAs = {
        val seconds = it.duration.inWholeSeconds
        if (seconds <= 0) {
            throw IllegalStateException("Duration in seconds MUST be a positive number.")
        }
        seconds.toULong()
    },
    decodeAs = {
        if (it > Long.MAX_VALUE.toULong()) {
            throw IllegalStateException("Duration in seconds is valid, but only values from `0` to `${Long.MAX_VALUE}` are supported by the currently used serializer.")
        }
        PositiveDuration(
            it.toLong().toDuration(DurationUnit.SECONDS)
        )
    }
)

