package at.asitplus.wallet.lib.oidvci

import com.benasher44.uuid.uuid4

interface CodeService {

    fun provideCode(): String

    fun verifyAndRemove(it: String): Boolean

}

class DefaultCodeService : CodeService {

    private val validCodes = mutableListOf<String>()

    override fun provideCode(): String {
        return uuid4().toString().also { validCodes += it }
    }

    override fun verifyAndRemove(it: String): Boolean {
        return validCodes.remove(it)
    }
}