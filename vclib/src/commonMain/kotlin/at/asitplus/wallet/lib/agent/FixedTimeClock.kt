package at.asitplus.wallet.lib.agent

import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

class FixedTimeClock(private val epochMilliseconds: Long) : Clock {

    override fun now() = Instant.fromEpochMilliseconds(epochMilliseconds)

}