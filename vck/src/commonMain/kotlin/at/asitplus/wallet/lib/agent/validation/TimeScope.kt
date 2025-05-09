package at.asitplus.wallet.lib.agent.validation

import kotlinx.datetime.Instant
import kotlin.time.Duration

data class TimeScope(
    val now: Instant,
    val timeLeeway: Duration,
) {
    val earliestTime = (now - timeLeeway)
    val latestTime = (now + timeLeeway)

    fun Instant.isTooEarly() = this < earliestTime
    fun Instant.isTooLate() = this > latestTime
}