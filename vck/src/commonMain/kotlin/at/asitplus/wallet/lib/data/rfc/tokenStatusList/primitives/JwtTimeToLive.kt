package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.double
import kotlinx.serialization.json.longOrNull
import kotlin.jvm.JvmInline
import kotlin.time.DurationUnit
import kotlin.time.toDuration

@Serializable
@JvmInline
value class JwtTimeToLive(private val value: PositiveJsonNumber) : TimeToLive {
    init {
        validate(value)
    }
    constructor(timeToLive: TimeToLive) : this(
        value = PositiveJsonNumber(
            JsonPrimitive(
                timeToLive.duration.value.inWholeSeconds
            )
        )
    )

    override val duration: PositiveDuration
        get() = value.toPositiveDuration()

    companion object {
        fun validate(value: PositiveJsonNumber) {
            value.toPositiveDuration()
        }

        private fun PositiveJsonNumber.toPositiveDuration() = PositiveDuration(
            value.longOrNull?.toDuration(DurationUnit.SECONDS)
                ?: value.double.toDuration(DurationUnit.SECONDS)
        )
    }
}

