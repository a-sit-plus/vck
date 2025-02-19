package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.getJcaPublicKey
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

actual open class PlatformCryptoShim actual constructor(actual val keyMaterial: KeyMaterial) {

    actual open fun encrypt(
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
            val ciphertext = jcaCiphertext.dropLast(128/ 8).toByteArray()
            val authtag = jcaCiphertext.takeLast(128 / 8).toByteArray()
            AuthenticatedCiphertext(ciphertext, authtag)
        } else {
            AuthenticatedCiphertext(jcaCiphertext, byteArrayOf())
        }
    }.wrap()

    actual open suspend fun decrypt(
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

    actual open fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray> = runCatching {
        val jvmKey = recipientKey.toCryptoPublicKey().getOrThrow().getJcaPublicKey().getOrThrow()
        KeyAgreement.getInstance(algorithm.jcaName).also {
            @OptIn(HazardousMaterials::class)
            it.init(ephemeralKey.key.jcaPrivateKey)
            it.doPhase(jvmKey, true)
        }.generateSecret()
    }.wrap()

    actual open fun performKeyAgreement(
        ephemeralKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray> = runCatching {
        val publicKey = ephemeralKey.toCryptoPublicKey().getOrThrow().getJcaPublicKey().getOrThrow()
        KeyAgreement.getInstance(algorithm.jcaName).also {
            @OptIn(HazardousMaterials::class)
            it.init(keyMaterial.getUnderLyingSigner().jcaPrivateKey)
            it.doPhase(publicKey, true)
        }.generateSecret()
    }.wrap()

    actual open fun hmac(
        key: ByteArray,
        algorithm: JweEncryption,
        input: ByteArray,
    ): KmmResult<ByteArray> = runCatching {
        Mac.getInstance(algorithm.jcaHmacName).also {
            it.init(SecretKeySpec(key, algorithm.jcaKeySpecName))
        }.doFinal(input)
    }.wrap()

}

