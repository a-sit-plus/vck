package at.asitplus.wallet.lib.oidvci

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

interface MapStore<T, U> {

    suspend fun put(key: T, value: U)

    suspend fun get(key: T): U?

    suspend fun remove(key: T): U?

}


/**
 * Holds map in memory, protected with a [Mutex]
 */
class DefaultMapStore<T, U> : MapStore<T, U> {

    private val mutex = Mutex()
    private val map = mutableMapOf<T, U>()

    override suspend fun put(key: T, value: U) {
        mutex.withLock { map.put(key, value) }
    }

    override suspend fun get(key: T) = mutex.withLock { map[key] }

    override suspend fun remove(key: T): U? = mutex.withLock { map.remove(key) }
}