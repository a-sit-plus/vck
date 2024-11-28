package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDurationSecondsJsonNumberSerializer
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline
import kotlin.time.Duration

/**
 * source: https://www.rfc-editor.org/rfc/rfc7519
 *
 * OPTIONAL.
 * The ttl (time to live) claim, if present, MUST specify the maximum amount of time,
 * in seconds, that the Status List Token can be cached by a consumer before a fresh
 * copy SHOULD be retrieved.
 * The value of the claim MUST be a positive number encoded in JSON as a number.
 */
@Serializable
@JvmInline
value class JwtTimeToLiveClaim(
    @Serializable(with = PositiveDurationSecondsJsonNumberSerializer::class)
    val positiveDuration: PositiveDuration,
) {
    data object Specification {
        const val CLAIM_NAME = "ttl"
    }

    fun isInvalid(
        resolvedAt: Instant,
        isInstantInThePast: (Instant) -> Boolean,
    ) = isInstantInThePast(
        resolvedAt + positiveDuration.duration
    )

    companion object {
        operator fun invoke(duration: Duration) = JwtTimeToLiveClaim(PositiveDuration(duration))
    }
}
