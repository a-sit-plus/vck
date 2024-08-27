package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.ECCurve.SECP_256_R_1
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.fromJcaPublicKey
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.getJcaPublicKey
import at.asitplus.signum.indispensable.jcaName
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.isAuthenticatedEncryption
import at.asitplus.signum.indispensable.josef.jcaKeySpecName
import at.asitplus.signum.indispensable.josef.jcaName
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.parseFromJca
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.supreme.sign.platformSpecifics
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.JCEECPublicKey
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

actual open class PlatformCryptoShim {

    actual  fun encrypt(
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


    actual  suspend fun decrypt(
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

    actual  fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray> = runCatching {
        val jvmKey = recipientKey.toCryptoPublicKey().transform { it1 -> it1.getJcaPublicKey() }.getOrThrow()

        KeyAgreement.getInstance(algorithm.jcaName).also {
            it.init(ephemeralKey.key.platformSpecifics.jcaPrivateKey)
            it.doPhase(
                jvmKey, true
            )
        }.generateSecret()
    }.wrap()

    actual  fun performKeyAgreement(
        ephemeralKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray> = runCatching {
        val publicKey = ephemeralKey.toCryptoPublicKey().getOrThrow().getJcaPublicKey().getOrThrow()
        TODO()
        /* KeyAgreement.getInstance(algorithm.jcaName).also {
             it.init(jvmKeyPairAdapter.keyPair.private)
             it.doPhase(publicKey, true)
         }.generateSecret()*/
    }.wrap()

}

