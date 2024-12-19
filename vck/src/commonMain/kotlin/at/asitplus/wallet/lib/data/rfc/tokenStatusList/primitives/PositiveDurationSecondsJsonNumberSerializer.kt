package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.double
import kotlinx.serialization.json.longOrNull
import kotlin.time.DurationUnit
import kotlin.time.toDuration

object PositiveDurationSecondsJsonNumberSerializer : TransformingSerializerTemplate<PositiveDuration, JsonPrimitive>(
    parent = JsonPrimitive.serializer(),
    encodeAs = {
        val duration = it.duration
        val seconds = it.duration.inWholeSeconds
        if (!duration.isPositive()) {
            throw IllegalStateException("Duration MUST be positive.")
        }
        if(duration.toIsoString().split(".").size == 1 && seconds != Long.MAX_VALUE) {
            // no second fractions and not coerced -> can be correctly represented as a long
            JsonPrimitive(seconds)
        } else {
            JsonPrimitive(it.duration.toDouble(DurationUnit.SECONDS))
        }
    },
    decodeAs = { jsonPrimitive ->
        PositiveDuration(
            jsonPrimitive.longOrNull?.toDuration(DurationUnit.SECONDS)
                ?: jsonPrimitive.double.toDuration(DurationUnit.SECONDS)
        )
    }
)