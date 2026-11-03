package at.asitplus.wallet.lib.agent.validation

import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Instant

data class TimeScope(
    val now: Instant,
    val timeLeeway: Duration,
) {
    /**
     * Java-safe constructor: Java can't call the primary constructor, because it takes the value class [Duration].
     * [timeLeewayMilliseconds] precedes [now], because the JVM signature would otherwise clash with the primary
     * constructor's, where [Duration] is a `long` too.
     */
    internal constructor(timeLeewayMilliseconds: Long, now: Instant) : this(now, timeLeewayMilliseconds.milliseconds)

    /** Java-safe accessor for [timeLeeway], in milliseconds. */
    val timeLeewayMilliseconds: Long
        get() = timeLeeway.inWholeMilliseconds

    val earliestTime = (now - timeLeeway)
    val latestTime = (now + timeLeeway)

    fun Instant.isTooEarly() = this < earliestTime
    fun Instant.isTooLate() = this > latestTime

    operator fun <T> invoke(block: TimeScope.() -> T) = block(this)
}