package at.asitplus.wallet.lib.oidvci

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Provides a simple map of keys of type [T] to values of type [U].
 * Mainly used in OID4VCI to hold state in [at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService]
 * and [WalletService].
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
 * Holds simple [map] in memory, protected with a [Mutex],
 * to ensure a basic form of thread-safety.
 */
class DefaultMapStore<T, U> : MapStore<T, U> {

    private val mutex = Mutex()
    private val map = mutableMapOf<T, U>()

    override suspend fun put(key: T, value: U) {
        mutex.withLock { map.put(key, value) }
    }

    override suspend fun get(key: T) = map[key]

    override suspend fun remove(key: T): U? = mutex.withLock { map.remove(key) }
}