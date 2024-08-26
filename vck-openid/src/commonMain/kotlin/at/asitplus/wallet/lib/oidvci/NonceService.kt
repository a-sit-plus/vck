package at.asitplus.wallet.lib.oidvci

import com.benasher44.uuid.uuid4
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

interface NonceService {

    suspend fun provideNonce(): String

    suspend fun verifyAndRemoveNonce(it: String): Boolean

}

/**
 * Holds nonces in memory, protected with a [Mutex].
 */
class DefaultNonceService : NonceService {

    private val mutex = Mutex()
    private val validNonces = mutableListOf<String>()

    override suspend fun provideNonce(): String {
        return uuid4().toString().also { mutex.withLock { validNonces += it } }
    }

    override suspend fun verifyAndRemoveNonce(it: String): Boolean {
        return mutex.withLock { validNonces.remove(it) }
    }
}