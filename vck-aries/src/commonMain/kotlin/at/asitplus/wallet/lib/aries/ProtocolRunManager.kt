package at.asitplus.wallet.lib.aries

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Holds a list of protocol runs for [ProtocolMessenger],
 * handling concurrency with a lock, as well as cleaning up
 * old (client did not send a message again) and finished runs.
 */
class ProtocolRunManager<T : ProtocolStateMachine<U>, U>(
    private val timeoutDuration: Duration = 60.minutes,
) {
    private val runMut = Mutex()
    private val mapProtocolRunLastContact = mutableMapOf<T, Instant>()

    suspend fun addProtocol(protocol: T) {
        cleanup()
        runMut.withLock {
            mapProtocolRunLastContact[protocol] = Clock.System.now()
        }
    }

    private suspend fun cleanup() {
        runMut.withLock {
            val outdatedOrFinished = mapProtocolRunLastContact
                .filter { ((Clock.System.now() - it.value) > timeoutDuration) or it.key.isFinished }
            outdatedOrFinished.forEach {
                mapProtocolRunLastContact.remove(it.key)
            }
        }
    }

    fun getActiveRuns(): List<T> {
        return mapProtocolRunLastContact.keys.toList()
    }

}


