package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.getJcaPublicKey
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.isAuthenticatedEncryption
import at.asitplus.signum.indispensable.josef.jcaKeySpecName
import at.asitplus.signum.indispensable.josef.jcaName
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import io.github.aakira.napier.Napier
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

actual open class PlatformCryptoShim actual constructor(actual val keyWithCert: KeyWithCert) {
companion object{
    init {
        Napier.d { "Adding BC" }
        Security.addProvider(BouncyCastleProvider())
    }
}

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
    ): KmmResult<ByteArray> = runCatching {
        val jvmKey = recipientKey.toCryptoPublicKey().transform { it1 -> it1.getJcaPublicKey() }.getOrThrow()

        KeyAgreement.getInstance(algorithm.jcaName).also {

            @OptIn(HazardousMaterials::class)
            it.init(ephemeralKey.key.jcaPrivateKey)
            it.doPhase(
                jvmKey, true
            )
        }.generateSecret()
    }.wrap()

    actual fun performKeyAgreement(
        ephemeralKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray> = runCatching {
        val publicKey = ephemeralKey.toCryptoPublicKey().getOrThrow().getJcaPublicKey().getOrThrow()

        KeyAgreement.getInstance(algorithm.jcaName).also {

            @OptIn(HazardousMaterials::class)
            it.init(keyWithCert.getUnderLyingSigner().jcaPrivateKey)
            it.doPhase(publicKey, true)
        }.generateSecret()
    }.wrap()


}

