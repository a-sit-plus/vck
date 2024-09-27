package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.josef.*
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

actual open class PlatformCryptoShim actual constructor(actual val keyMaterial: KeyMaterial) {

    actual fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<AuthenticatedCiphertext> = runCatching {
        val jcaCiphertext = Cipher.getInstance(algorithm.jcaName).also {
            if (algorithm.isAuthenticatedEncryption) {
                it.init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpecName),
                    GCMParameterSpec(algorithm.ivLengthBits, iv)
                )
                it.updateAAD(aad)
            } else {
                it.init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpecName),
                )
            }
        }.doFinal(input)
        if (algorithm.isAuthenticatedEncryption) {
            val ciphertext = jcaCiphertext.dropLast(algorithm.ivLengthBits / 8).toByteArray()
            val authtag = jcaCiphertext.takeLast(algorithm.ivLengthBits / 8).toByteArray()
            AuthenticatedCiphertext(ciphertext, authtag)
        } else {
            AuthenticatedCiphertext(jcaCiphertext, byteArrayOf())
        }
    }.wrap()


    actual suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<ByteArray> = runCatching {
        Cipher.getInstance(algorithm.jcaName).also {
            if (algorithm.isAuthenticatedEncryption) {
                it.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpecName),
                    GCMParameterSpec(algorithm.ivLengthBits, iv)
                )
                it.updateAAD(aad)
            } else {
                it.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpecName),
                )
            }
        }.doFinal(input + authTag)
    }.wrap()

    actual fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray> {
        return KmmResult.success("sharedSecret-${algorithm.identifier}".encodeToByteArray())
    }

    actual fun performKeyAgreement(ephemeralKey: JsonWebKey, algorithm: JweAlgorithm): KmmResult<ByteArray> {
        return KmmResult.success("sharedSecret-${algorithm.identifier}".encodeToByteArray())
    }

    actual fun hmac(
        key: ByteArray,
        algorithm: JweEncryption,
        input: ByteArray,
    ): KmmResult<ByteArray> = runCatching {
        Mac.getInstance(algorithm.jcaHmacName).also {
            it.init(SecretKeySpec(key, algorithm.jcaKeySpecName))
        }.doFinal(input)
    }.wrap()

}

