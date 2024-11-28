package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable

@Serializable(with = TimeToLiveSerializer::class)
interface TimeToLive {
    val duration: PositiveDuration

    fun isInvalid(
        resolvedAt: Instant,
        isInstantInThePast: (Instant) -> Boolean,
    ) = isInstantInThePast(
        resolvedAt + duration.value
    )
}