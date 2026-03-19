package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline
import kotlin.time.Duration

@Serializable
@JvmInline
value class PositiveDuration(val duration: Duration) {
    init {
        validate(duration)
    }

    companion object {
        fun validate(duration: Duration) {
            if (!duration.isPositive()) {
                throw IllegalArgumentException("Duration must be positive.")
            }
        }
    }
}

