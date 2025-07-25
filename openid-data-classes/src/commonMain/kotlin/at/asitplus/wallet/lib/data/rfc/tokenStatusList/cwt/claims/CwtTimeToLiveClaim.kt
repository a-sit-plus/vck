package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDurationSecondsULongSerializer
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline
import kotlin.time.Duration

/**
 * 65534 (time to live): OPTIONAL. Unsigned integer (Major Type 0). The time to live claim, if
 * present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be
 * cached by a consumer before a fresh copy SHOULD be retrieved. The value of the claim MUST be a
 * positive number.
 */
@Serializable
@JvmInline
value class CwtTimeToLiveClaim(
    @Serializable(with = PositiveDurationSecondsULongSerializer::class)
    val positiveDuration: PositiveDuration,
) {
    data object Specification {
        const val CLAIM_NAME = "ttl"
        const val CLAIM_KEY = 65534L
    }

    fun isInvalid(
        resolvedAt: Instant,
        isInstantInThePast: (Instant) -> Boolean,
    ) = isInstantInThePast(
        resolvedAt + positiveDuration.duration
    )

    companion object {
        operator fun invoke(duration: Duration) = CwtTimeToLiveClaim(PositiveDuration(duration))
    }
}