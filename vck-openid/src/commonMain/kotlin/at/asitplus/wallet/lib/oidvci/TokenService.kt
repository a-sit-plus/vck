package at.asitplus.wallet.lib.oidvci

import com.benasher44.uuid.uuid4

interface TokenService {

    fun provideToken(): String

    fun verifyToken(it: String): Boolean

    fun verifyAndRemoveToken(it: String): Boolean

}

class DefaultTokenService : TokenService {

    private val validTokens = mutableListOf<String>()

    override fun provideToken(): String {
        return uuid4().toString().also { validTokens += it }
    }

    override fun verifyToken(it: String): Boolean {
        return validTokens.contains(it)
    }

    override fun verifyAndRemoveToken(it: String): Boolean {
        return validTokens.remove(it)
    }
}