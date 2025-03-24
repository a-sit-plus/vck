package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.josef.JweEncryption
import io.github.aakira.napier.Napier
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

actual open class PlatformCryptoShim {

    companion object {
        init {
            Napier.d { "Adding BC" }
            Security.addProvider(BouncyCastleProvider())
        }
    }
    private val delegate = AndroidJvmPlatformCryptoShim()

    actual open fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<AuthenticatedCiphertext> = delegate.encrypt(key, iv, aad, input, algorithm)

    actual open suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<ByteArray> = delegate.decrypt(key, iv, aad, input, authTag, algorithm)


    actual open fun hmac(
        key: ByteArray,
        algorithm: JweEncryption,
        input: ByteArray,
    ): KmmResult<ByteArray> = delegate.hmac(key, algorithm, input)

}