package at.asitplus.wallet.lib.agent.validation

import kotlin.time.Instant
import kotlin.time.Duration

data class TimeScope(
    val now: Instant,
    val timeLeeway: Duration,
) {
    val earliestTime = (now - timeLeeway)
    val latestTime = (now + timeLeeway)

    fun Instant.isTooEarly() = this < earliestTime
    fun Instant.isTooLate() = this > latestTime

    operator fun <T> invoke(block: TimeScope.() -> T) = block(this)
}