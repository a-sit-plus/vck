package at.asitplus.wallet.lib

interface ZlibService {

    fun compress(input: ByteArray): ByteArray?

    fun decompress(input: ByteArray): ByteArray?

}

expect class DefaultZlibService() : ZlibService