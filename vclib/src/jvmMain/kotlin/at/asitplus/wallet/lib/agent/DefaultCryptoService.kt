@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.*
import at.asitplus.crypto.datatypes.ECCurve.SECP_256_R_1
import at.asitplus.crypto.datatypes.cose.CoseKey
import at.asitplus.crypto.datatypes.cose.toCoseAlgorithm
import at.asitplus.crypto.datatypes.cose.toCoseKey
import at.asitplus.crypto.datatypes.jws.*
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.datatypes.pki.X509CertificateExtension
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


actual open class DefaultCryptoService : CryptoService {

    actual final override val keyPairAdapter: KeyPairAdapter

    private val jvmKeyPairAdapter: JvmKeyPairAdapter

    actual constructor(keyPairAdapter: KeyPairAdapter) {
        assert(keyPairAdapter is JvmKeyPairAdapter)
        keyPairAdapter as JvmKeyPairAdapter
        this.jvmKeyPairAdapter = keyPairAdapter
        this.keyPairAdapter = keyPairAdapter
    }

    /**
     * Constructor which allows all public keys implemented in `KMP-Crypto`
     * Because RSA needs the algorithm parameter to be useful (as it cannot be inferred from the key)
     * it's mandatory
     * Also used for custom certificates
     */
    constructor(
        keyPair: KeyPair,
        algorithm: X509SignatureAlgorithm,
    ) {
        this.jvmKeyPairAdapter = JvmKeyPairAdapter(keyPair, algorithm, null)
        this.keyPairAdapter = jvmKeyPairAdapter
    }

    actual override suspend fun doSign(input: ByteArray): KmmResult<CryptoSignature> = runCatching {
        val sig = keyPairAdapter.signingAlgorithm.algorithm.getJCASignatureInstance().getOrThrow().apply {
            initSign(jvmKeyPairAdapter.keyPair.private)
            update(input)
        }.sign()
        CryptoSignature.parseFromJca(sig, keyPairAdapter.signingAlgorithm)
    }.wrap()

    actual override fun encrypt(
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


    actual override suspend fun decrypt(
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

    actual override fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray> = runCatching {
        require(ephemeralKey is JvmEphemeralKeyHolder) { "JVM Type expected" }
        val jvmKey = recipientKey.toCryptoPublicKey().transform { it1 -> it1.getJcaPublicKey() }.getOrThrow()
        KeyAgreement.getInstance(algorithm.jcaName).also {
            it.init(ephemeralKey.keyPair.private)
            it.doPhase(
                jvmKey, true
            )
        }.generateSecret()
    }.wrap()

    actual override fun performKeyAgreement(
        ephemeralKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray> = runCatching {
        val parameterSpec = ECNamedCurveTable.getParameterSpec(ephemeralKey.curve?.jcaName)
        val xBigInteger = BigInteger(1, ephemeralKey.x)
        val yBigInteger = BigInteger(1, ephemeralKey.y)
        val ecPoint = parameterSpec.curve.validatePoint(xBigInteger, yBigInteger)
        val ecPublicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)
        val publicKey = JCEECPublicKey("EC", ecPublicKeySpec)

        KeyAgreement.getInstance(algorithm.jcaName).also {
            it.init(jvmKeyPairAdapter.keyPair.private)
            it.doPhase(publicKey, true)
        }.generateSecret()
    }.wrap()

    actual override fun generateEphemeralKeyPair(ecCurve: ECCurve): KmmResult<EphemeralKeyHolder> =
        KmmResult.success(JvmEphemeralKeyHolder(ecCurve))

    actual override fun messageDigest(input: ByteArray, digest: Digest): KmmResult<ByteArray> = runCatching {
        MessageDigest.getInstance(digest.jcaName).digest(input)
    }.wrap()

}

class JvmKeyPairAdapter(
    val keyPair: KeyPair,
    override val signingAlgorithm: X509SignatureAlgorithm,
    override val certificate: X509Certificate?
) : KeyPairAdapter {
    override val publicKey: CryptoPublicKey
        get() = CryptoPublicKey.fromJcaPublicKey(keyPair.public).getOrThrow()
    override val identifier: String
        get() = publicKey.didEncoded
    override val jsonWebKey: JsonWebKey
        get() = publicKey.toJsonWebKey()
    override val coseKey: CoseKey
        get() = publicKey.toCoseKey(signingAlgorithm.toCoseAlgorithm().getOrThrow()).getOrThrow()
}

actual fun RandomKeyPairAdapter(extensions: List<X509CertificateExtension>): KeyPairAdapter {
    val keyPair = genEc256KeyPair()
    val signingAlgorithm = X509SignatureAlgorithm.ES256
    val publicKey = CryptoPublicKey.fromJcaPublicKey(keyPair.public).getOrThrow()
    val certificate = X509Certificate.generateSelfSignedCertificate(publicKey, signingAlgorithm, extensions) {
        runCatching {
            CryptoSignature.parseFromJca(signingAlgorithm.getJCASignatureInstance().getOrThrow().apply {
                initSign(keyPair.private)
                update(it)
            }.sign(), signingAlgorithm)
        }.wrap()
    }
    return JvmKeyPairAdapter(keyPair, signingAlgorithm, certificate)
}

private fun genEc256KeyPair(): KeyPair =
    KeyPairGenerator.getInstance("EC")
        .also { it.initialize(SECP_256_R_1.keyLengthBits.toInt()) }
        .genKeyPair()

actual open class DefaultVerifierCryptoService : VerifierCryptoService {

    actual override val supportedAlgorithms: List<X509SignatureAlgorithm> =
        X509SignatureAlgorithm.entries.filter { it.isEc }

    actual override fun verify(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: X509SignatureAlgorithm,
        publicKey: CryptoPublicKey,
    ): KmmResult<Boolean> = runCatching {
        algorithm.getJCASignatureInstance().getOrThrow().apply {
            initVerify(publicKey.getJcaPublicKey().getOrThrow())
            update(input)
        }.verify(signature.jcaSignatureBytes)
    }.wrap()
}

open class JvmEphemeralKeyHolder(private val ecCurve: ECCurve) : EphemeralKeyHolder {

    val keyPair: KeyPair =
        KeyPairGenerator.getInstance("EC").also { it.initialize(ecCurve.keyLengthBits.toInt()) }.genKeyPair()

    override val publicJsonWebKey: JsonWebKey? by lazy {
        CryptoPublicKey.fromJcaPublicKey(keyPair.public).map { it.toJsonWebKey() }.getOrNull()
    }

}
