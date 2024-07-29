package at.asitplus.wallet.lib.oidvci

import com.benasher44.uuid.uuid4

interface CodeService {

    fun provideCode(): String

    fun verifyCode(it: String): Boolean

}

class DefaultCodeService : CodeService {

    private val validCodes = mutableListOf<String>()

    override fun provideCode(): String {
        return uuid4().toString().also { validCodes += it }
    }

    override fun verifyCode(it: String): Boolean {
        return validCodes.remove(it)
    }
}