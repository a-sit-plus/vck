package at.asitplus.wallet.lib

import com.benasher44.uuid.uuid4
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

interface NonceService {
    suspend fun provideNonce(): String
    suspend fun verifyNonce(it: String): Boolean
    suspend fun verifyAndRemoveNonce(it: String): Boolean
}

class DefaultNonceService : NonceService {
    private val mutex = Mutex()
    private val values = mutableListOf<String>()

    override suspend fun provideNonce() = uuid4().toString().also { mutex.withLock { values += it } }

    override suspend fun verifyNonce(it: String) = values.contains(it)

    override suspend fun verifyAndRemoveNonce(it: String) =
        mutex.withLock { values.remove(it) }
}
