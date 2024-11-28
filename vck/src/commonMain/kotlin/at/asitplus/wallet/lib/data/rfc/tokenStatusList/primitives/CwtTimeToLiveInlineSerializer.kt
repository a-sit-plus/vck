package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.builtins.serializer
import kotlin.time.DurationUnit
import kotlin.time.toDuration

object CwtTimeToLiveInlineSerializer : TransformingSerializerTemplate<CwtTimeToLive, ULong>(
    parent = ULong.serializer(),
    encodeAs = {
        it.duration.inWholeSeconds.toULong()
    },
    decodeAs = {
        CwtTimeToLive(
            PositiveDuration(
                it.toLong().toDuration(DurationUnit.SECONDS)
            )
        )
    }
)