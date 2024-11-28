package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.builtins.serializer
import kotlin.time.DurationUnit
import kotlin.time.toDuration

object JwtTimeToLiveInlineSerializer : TransformingSerializerTemplate<JwtTimeToLive, Double>(
    parent = Double.serializer(),
    decodeAs = {
        JwtTimeToLive(
            PositiveDuration(
                it.toDuration(DurationUnit.SECONDS)
            )
        )
    },
    encodeAs = {
        it.duration.inWholeNanoseconds.toDouble() / 1_000_000_000
    }
)