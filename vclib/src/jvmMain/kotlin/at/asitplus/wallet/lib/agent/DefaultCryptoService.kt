package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.*
import at.asitplus.crypto.datatypes.EcCurve.SECP_256_R_1
import at.asitplus.crypto.datatypes.asn1.ensureSize
import at.asitplus.crypto.datatypes.cose.CoseAlgorithm
import at.asitplus.crypto.datatypes.jws.*
import at.asitplus.crypto.datatypes.jws.JwsExtensions.convertToAsn1Signature
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.JCEECPublicKey
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.util.io.pem.PemReader
import java.io.InputStream
import java.math.BigInteger
import java.security.*
import java.security.cert.Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.absoluteValue
import kotlin.random.Random
import kotlin.time.Duration.Companion.days


actual open class DefaultCryptoService : CryptoService {

    private val ecCurve: EcCurve = SECP_256_R_1
    private val keyPair: KeyPair
    private val cryptoPublicKey: CryptoPublicKey
    final override val certificate: ByteArray

    actual constructor() {
        this.keyPair =
            KeyPairGenerator.getInstance("EC").also { it.initialize(ecCurve.keyLengthBits.toInt()) }.genKeyPair()
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        // TODO RSA Test
        this.cryptoPublicKey = CryptoPublicKey.Ec(curve = SECP_256_R_1, x = keyX, y = keyY)
        this.certificate = generateSelfSignedCertificate()
    }

    constructor(keyPair: KeyPair) {
        this.keyPair = keyPair
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        // TODO RSA Test
        this.cryptoPublicKey = CryptoPublicKey.Ec(curve = SECP_256_R_1, x = keyX, y = keyY)
        this.certificate = generateSelfSignedCertificate()
    }

    constructor(keyPair: KeyPair, certificate: Certificate) {
        this.keyPair = keyPair
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        // TODO RSA Test
        this.cryptoPublicKey = CryptoPublicKey.Ec(curve = SECP_256_R_1, x = keyX, y = keyY)
        this.certificate = certificate.encoded
    }

    private fun generateSelfSignedCertificate(): ByteArray {
        val notBeforeDate = Date.from(Instant.now())
        val notAfterDate = Date.from(Instant.now().plusSeconds(30.days.inWholeSeconds))
        val serialNumber: BigInteger = BigInteger.valueOf(Random.nextLong().absoluteValue)
        val issuer = X500Name("CN=DefaultCryptoService")
        val builder = X509v3CertificateBuilder(
            /* issuer = */ issuer,
            /* serial = */ serialNumber,
            /* notBefore = */ notBeforeDate,
            /* notAfter = */ notAfterDate,
            /* subject = */ issuer,
            /* publicKeyInfo = */ SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        )
        val contentSigner: ContentSigner = JcaContentSignerBuilder(JwsAlgorithm.ES256.jcaName).build(keyPair.private)
        val certificateHolder = builder.build(contentSigner)
        return certificateHolder.encoded
    }

    override val jwsAlgorithm = JwsAlgorithm.ES256

    override val coseAlgorithm = CoseAlgorithm.ES256

    override fun toPublicKey() = cryptoPublicKey

    override suspend fun sign(input: ByteArray): KmmResult<ByteArray> =
        try {
            val signed = Signature.getInstance(jwsAlgorithm.jcaName).apply {
                initSign(keyPair.private)
                update(input)
            }.sign()
            KmmResult.success(signed)
        } catch (e: Throwable) {
            KmmResult.failure(e)
        }

    override fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<AuthenticatedCiphertext> = try {
        val jcaCiphertext = Cipher.getInstance(algorithm.jcaName).also {
            it.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, algorithm.jcaKeySpecName),
                GCMParameterSpec(algorithm.ivLengthBits, iv)
            )
            it.updateAAD(aad)
        }.doFinal(input)
        val ciphertext = jcaCiphertext.dropLast(algorithm.ivLengthBits / 8).toByteArray()
        val authtag = jcaCiphertext.takeLast(algorithm.ivLengthBits / 8).toByteArray()
        KmmResult.success(AuthenticatedCiphertext(ciphertext, authtag))
    } catch (e: Throwable) {
        KmmResult.failure(e)
    }

    override suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<ByteArray> = try {
        val plaintext = Cipher.getInstance(algorithm.jcaName).also {
            it.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, algorithm.jcaKeySpecName),
                GCMParameterSpec(algorithm.ivLengthBits, iv)
            )
            it.updateAAD(aad)
        }.doFinal(input + authTag)
        KmmResult.success(plaintext)
    } catch (e: Throwable) {
        KmmResult.failure(e)
    }

    override fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray> {
        require(ephemeralKey is JvmEphemeralKeyHolder) { "JVM Type expected" }
        return try {
            val secret = KeyAgreement.getInstance(algorithm.jcaName).also {
                it.init(ephemeralKey.keyPair.private)
                it.doPhase(recipientKey.toCryptoPublicKey()?.getPublicKey(), true)
            }.generateSecret()
            KmmResult.success(secret)
        } catch (e: Throwable) {
            KmmResult.failure(e)
        }
    }

    override fun performKeyAgreement(ephemeralKey: JsonWebKey, algorithm: JweAlgorithm): KmmResult<ByteArray> = try {
        val parameterSpec = ECNamedCurveTable.getParameterSpec(ephemeralKey.curve?.jcaName)
        val ecPoint = parameterSpec.curve.validatePoint(BigInteger(1, ephemeralKey.x), BigInteger(1, ephemeralKey.y))
        val ecPublicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)
        val publicKey = JCEECPublicKey("EC", ecPublicKeySpec)
        val secret = KeyAgreement.getInstance(algorithm.jcaName).also {
            it.init(keyPair.private)
            it.doPhase(publicKey, true)
        }.generateSecret()
        KmmResult.success(secret)
    } catch (e: Throwable) {
        KmmResult.failure(e)
    }

    override fun generateEphemeralKeyPair(ecCurve: EcCurve): KmmResult<EphemeralKeyHolder> =
        KmmResult.success(JvmEphemeralKeyHolder(ecCurve))

    override fun messageDigest(input: ByteArray, digest: Digest): KmmResult<ByteArray> = try {
        KmmResult.success(MessageDigest.getInstance(digest.jcaName).digest(input))
    } catch (e: Throwable) {
        KmmResult.failure(e)
    }

}

actual open class DefaultVerifierCryptoService : VerifierCryptoService {

    override fun verify(
        input: ByteArray,
        signature: ByteArray,
        algorithm: JwsAlgorithm,
        publicKey: CryptoPublicKey,
    ): KmmResult<Boolean> {
        // TODO RSA
        if (publicKey !is CryptoPublicKey.Ec) {
            return KmmResult.failure(IllegalArgumentException("Public key is not an EC key"))
        }
        return try {
            val asn1Signature = signature.convertToAsn1Signature(publicKey.curve.signatureLengthBytes.toInt())
            val result = Signature.getInstance(algorithm.jcaName).apply {
                initVerify(publicKey.getPublicKey())
                update(input)
            }.verify(asn1Signature)
            KmmResult.success(result)
        } catch (e: Throwable) {
            KmmResult.failure(e)
        }
    }

}


open class JvmEphemeralKeyHolder(private val ecCurve: EcCurve) : EphemeralKeyHolder {

    val keyPair: KeyPair =
        KeyPairGenerator.getInstance("EC").also { it.initialize(ecCurve.keyLengthBits.toInt()) }.genKeyPair()

    override fun toPublicJsonWebKey(): JsonWebKey {
        return CryptoPublicKey.fromJcaKey(keyPair.public)?.toJsonWebKey()
            ?: throw IllegalArgumentException("Could not Convert Key")
    }

}

fun loadDocSigner(str: InputStream): ECPublicKey {
    val factory = KeyFactory.getInstance("EC")
    val pem = PemReader(str.reader()).readPemObject()
    val encoded = pem.content
    val pubKeySpec = X509EncodedKeySpec(encoded)
    return factory.generatePublic(pubKeySpec) as ECPublicKey

}
