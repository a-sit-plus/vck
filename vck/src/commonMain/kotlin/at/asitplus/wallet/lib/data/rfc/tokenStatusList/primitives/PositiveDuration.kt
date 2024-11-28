package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import kotlin.jvm.JvmInline
import kotlin.time.Duration

@JvmInline
value class PositiveDuration(
    val value: Duration,
) {
    companion object {
        fun validate(value: Duration) {
            if(value <= Duration.ZERO) {
                throw IllegalArgumentException("Argument `value` must be a positive duration.")
            }
        }
    }

    init {
        validate(value)
    }
}