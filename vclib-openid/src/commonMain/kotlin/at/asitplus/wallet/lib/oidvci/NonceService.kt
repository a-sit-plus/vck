package at.asitplus.wallet.lib.oidvci

import com.benasher44.uuid.uuid4

interface NonceService {

    fun provideNonce(): String

    fun verifyAndRemoveNonce(it: String): Boolean

}

class DefaultNonceService : NonceService {

    private val validNonces = mutableListOf<String>()

    override fun provideNonce(): String {
        return uuid4().toString().also { validNonces += it }
    }

    override fun verifyAndRemoveNonce(it: String): Boolean {
        return validNonces.remove(it)
    }
}