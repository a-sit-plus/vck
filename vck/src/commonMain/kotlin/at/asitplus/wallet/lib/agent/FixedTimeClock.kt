package at.asitplus.wallet.lib.agent

import kotlin.time.Clock
import kotlin.time.Instant

class FixedTimeClock(private val epochMilliseconds: Long) : Clock {

    override fun now() = Instant.fromEpochMilliseconds(epochMilliseconds)

}