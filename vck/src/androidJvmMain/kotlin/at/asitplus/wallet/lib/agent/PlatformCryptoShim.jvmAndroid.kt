package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.agent.AuthenticatedCiphertext
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.KeyMaterial
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AndroidJvmPlatformCryptoShim  {

    fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<AuthenticatedCiphertext> = runCatching {
        val jcaCiphertext = Cipher.getInstance(algorithm.jcaName).also {
            it.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, algorithm.jcaKeySpecName),
                IvParameterSpec(iv)
            )
            if (algorithm.isAuthenticatedEncryption) {
                it.updateAAD(aad)
            }
        }.doFinal(input)
        if (algorithm.isAuthenticatedEncryption) {
            //FOR AES AEAD it is always block size
            val ciphertext = jcaCiphertext.dropLast(128 / 8).toByteArray()
            val authtag = jcaCiphertext.takeLast(128 / 8).toByteArray()
            AuthenticatedCiphertext(ciphertext, authtag)
        } else {
            AuthenticatedCiphertext(jcaCiphertext, byteArrayOf())
        }
    }.wrap()

     suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<ByteArray> = runCatching {
        val wholeInput = input + if (algorithm.isAuthenticatedEncryption) authTag else byteArrayOf()
        Cipher.getInstance(algorithm.jcaName).also {
            it.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, algorithm.jcaKeySpecName),
                IvParameterSpec(iv)
            )
            if (algorithm.isAuthenticatedEncryption) {
                it.updateAAD(aad)
            }
        }.doFinal(wholeInput)
    }.wrap()


     fun hmac(
        key: ByteArray,
        algorithm: JweEncryption,
        input: ByteArray,
    ): KmmResult<ByteArray> = runCatching {
        Mac.getInstance(algorithm.jcaHmacName).also {
            it.init(SecretKeySpec(key, algorithm.jcaKeySpecName))
        }.doFinal(input)
    }.wrap()
}

