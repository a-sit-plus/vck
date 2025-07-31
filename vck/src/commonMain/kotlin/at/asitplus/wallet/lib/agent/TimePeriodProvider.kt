package at.asitplus.wallet.lib.agent

import kotlin.time.Clock
import kotlin.time.Instant

interface TimePeriodProvider {

    fun getCurrentTimePeriod(clock: Clock): Int

    fun getRelevantTimePeriods(clock: Clock): List<Int>

    fun getTimePeriodFor(instant: Instant): Int
}

object FixedTimePeriodProvider : TimePeriodProvider {
    const val timePeriod = 1
    override fun getCurrentTimePeriod(clock: Clock): Int = timePeriod
    override fun getRelevantTimePeriods(clock: Clock): List<Int> = listOf(timePeriod)
    override fun getTimePeriodFor(instant: Instant): Int = timePeriod
}
