package at.asitplus.wallet.lib.utils

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Provides a simple map of keys of type [T] to values of type [U].
 * Mainly used in OID4VCI to hold state in [at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService]
 * and [at.asitplus.wallet.lib.oidvci.WalletService].
 * Can be implemented to provide replication across different instances of the enclosing application.
 */
interface MapStore<T, U> {

    /**
     * Implementers: Associate [key] with [value]
     */
    suspend fun put(key: T, value: U)

    /**
     * Implementers: Return the value associated with [key]
     */
    suspend fun get(key: T): U?

    /**
     * Implementers: Return and remove the value associated with [key]
     */
    suspend fun remove(key: T): U?

}


/**
 * Holds simple [map] in memory, with all entries having a lifetime of [lifetime],
 * protected with a [Mutex], to ensure a basic form of thread-safety.
 * Beware that array types are neither supported as the key type `T` nor the value type `U`,
 * as this would mess up equality checks (and should not be needed anyway).
 */
class DefaultMapStore<T, U>(
    val lifetime: Duration = 10.minutes,
    val clock: Clock = Clock.System,
    /** Will check for expired entries when map reaches [sizeToCheckForExpiration] entries */
    val sizeToCheckForExpiration: UInt = 100U,
) : MapStore<T, U> {

    init {
        require(lifetime > Duration.ZERO) { "lifetime must be > 0" }
    }

    data class Holder<U>(
        val value: U,
        val expiration: Instant,
    ) {
        init {
            require(value !is Array<*>) { "Arrays are not supported as values" }
        }
    }

    private val mutex = Mutex()
    private val map = mutableMapOf<T, Holder<U>>()

    /** Throws when using array types, as this is the best we can do with the type system as it is now. */
    override suspend fun put(key: T, value: U) {
        require(value !is Array<*>) { "Arrays are not supported as values" }
        require(key !is Array<*>) { "Arrays are not supported as keys" }
        mutex.withLock {
            map[key] = Holder(value, clock.now() + lifetime)
            if (map.size >= sizeToCheckForExpiration.toInt()) {
                cleanupExpiredLocked()
            }
        }
    }

    private fun cleanupExpiredLocked() {
        map.entries.iterator().let {
            while (it.hasNext()) {
                if (it.next().value.expiration < clock.now()) {
                    it.remove()
                }
            }
        }
    }

    override suspend fun get(key: T) = mutex.withLock {
        map[key]?.let { entry ->
            if (entry.expiration < clock.now()) {
                map.remove(key)
                null
            } else {
                entry.value
            }
        }
    }

    override suspend fun remove(key: T): U? = mutex.withLock {
        map.remove(key)?.let { entry ->
            if (entry.expiration < clock.now()) {
                null
            } else {
                entry.value
            }
        }
    }
}
