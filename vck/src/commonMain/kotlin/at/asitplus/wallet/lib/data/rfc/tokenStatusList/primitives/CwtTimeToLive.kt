package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline
import kotlin.time.DurationUnit
import kotlin.time.toDuration

@Serializable
@JvmInline
value class CwtTimeToLive(private val value: ULong) : TimeToLive {
    override val duration: PositiveDuration
        get() = value.toPositiveDuration()

    companion object {
        private fun ULong.toPositiveDuration(): PositiveDuration {
            if (this > Long.MAX_VALUE.toULong()) {
                throw IllegalStateException("Value is valid, but not supported by the current implementation.")
            }
            return PositiveDuration(
                this.toLong().toDuration(DurationUnit.SECONDS)
            )
        }

        fun fromTimeToLive(timeToLive: TimeToLive) = CwtTimeToLive(
            timeToLive.duration.value.inWholeSeconds.let {
                if (it <= 0) {
                    throw IllegalStateException("Time to live duration in seconds should be a positive number.")
                }
                it.toULong()
            }
        )

        fun validate(value: ULong) {
            value.toPositiveDuration()
        }
    }

    init {
        validate(value)
    }
}

