package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.cbor.CoseAlgorithm
import at.asitplus.wallet.lib.cbor.CoseEllipticCurve
import at.asitplus.wallet.lib.cbor.CoseEllipticCurve.P256
import at.asitplus.wallet.lib.cbor.CoseKey
import at.asitplus.wallet.lib.cbor.CoseKeyType.EC2
import at.asitplus.wallet.lib.jws.EcCurve
import at.asitplus.wallet.lib.jws.EcCurve.SECP_256_R_1
import at.asitplus.wallet.lib.jws.JsonWebKey
import at.asitplus.wallet.lib.jws.JweAlgorithm
import at.asitplus.wallet.lib.jws.JweEncryption
import at.asitplus.wallet.lib.jws.JwkType.EC
import at.asitplus.wallet.lib.jws.JwsAlgorithm
import at.asitplus.wallet.lib.jws.JwsExtensions.convertToAsn1Signature
import at.asitplus.wallet.lib.jws.JwsExtensions.ensureSize
import at.asitplus.wallet.lib.jws.MultibaseHelper
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
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Date
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
        this.keyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(ecCurve.keyLengthBits) }.genKeyPair()
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyId = MultibaseHelper.calcKeyId(SECP_256_R_1, keyX, keyY)!!
        this.cryptoPublicKey = CryptoPublicKey.Ec(curve = SECP_256_R_1, keyId = keyId, x = keyX, y = keyY)
        this.certificate = generateSelfSignedCertificate()
    }

    constructor(keyPair: KeyPair) {
        this.keyPair = keyPair
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyId = MultibaseHelper.calcKeyId(SECP_256_R_1, keyX, keyY)!!
        this.cryptoPublicKey = CryptoPublicKey.Ec(curve = SECP_256_R_1, keyId = keyId, x = keyX, y = keyY)
        this.certificate = generateSelfSignedCertificate()
    }

    constructor(keyPair: KeyPair, certificate: Certificate) {
        this.keyPair = keyPair
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyId = MultibaseHelper.calcKeyId(SECP_256_R_1, keyX, keyY)!!
        this.cryptoPublicKey = CryptoPublicKey.Ec(curve = SECP_256_R_1, keyId = keyId, x = keyX, y = keyY)
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
                it.doPhase(recipientKey.getPublicKey(), true)
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
        publicKey: JsonWebKey
    ): KmmResult<Boolean> {
        return try {
            val asn1Signature = signature.convertToAsn1Signature(publicKey.curve?.signatureLengthBytes ?: 32)
            val result = Signature.getInstance(algorithm.jcaName).apply {
                initVerify(publicKey.getPublicKey())
                update(input)
            }.verify(asn1Signature)
            KmmResult.success(result)
        } catch (e: Throwable) {
            KmmResult.failure(e)
        }
    }

    override fun verify(
        input: ByteArray,
        signature: ByteArray,
        algorithm: CoseAlgorithm,
        publicKey: CoseKey
    ): KmmResult<Boolean> {
        return try {
            val asn1Signature = signature.convertToAsn1Signature(publicKey.curve?.signatureLengthBytes ?: 32)
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

actual object CryptoUtils {

    actual fun extractPublicKeyFromX509Cert(it: ByteArray): JsonWebKey? = kotlin.runCatching {
        val pubKey = CertificateFactory.getInstance("X.509").generateCertificate(it.inputStream()).publicKey
        if (pubKey is ECPublicKey) JsonWebKey.fromJcaKey(pubKey, SECP_256_R_1) else null
    }.getOrNull()

    actual fun extractCoseKeyFromX509Cert(it: ByteArray): CoseKey? = kotlin.runCatching {
        val pubKey = CertificateFactory.getInstance("X.509").generateCertificate(it.inputStream()).publicKey
        if (pubKey is ECPublicKey) CoseKey.fromJcaKey(pubKey, P256) else null
    }.getOrNull()

}

val JwsAlgorithm.jcaName
    get() = when (this) {
        JwsAlgorithm.ES256 -> "SHA256withECDSA"
    }

val CoseAlgorithm.jcaName
    get() = when (this) {
        CoseAlgorithm.ES256 -> "SHA256withECDSA"
        CoseAlgorithm.ES384 -> "SHA384withECDSA"
        CoseAlgorithm.ES512 -> "SHA512withECDSA"
        CoseAlgorithm.HMAC256_256 -> "HmacSHA256"
    }

val Digest.jcaName
    get() = when (this) {
        Digest.SHA256 -> "SHA-256"
    }

val JweEncryption.jcaName
    get() = when (this) {
        JweEncryption.A256GCM -> "AES/GCM/NoPadding"
    }

val JweEncryption.jcaKeySpecName
    get() = when (this) {
        JweEncryption.A256GCM -> "AES"
    }

val JweAlgorithm.jcaName
    get() = when (this) {
        JweAlgorithm.ECDH_ES -> "ECDH"
    }

val EcCurve.jcaName
    get() = when (this) {
        SECP_256_R_1 -> "secp256r1"
    }

val CoseEllipticCurve.jcaName
    get() = when (this) {
        P256 -> "P-256"
        CoseEllipticCurve.P384 -> "P-384"
        CoseEllipticCurve.P521 -> "P-521"
    }

fun JsonWebKey.getPublicKey(): PublicKey {
    return toPublicKey(curve?.jcaName, x, y)
}

fun CoseKey.getPublicKey(): PublicKey {
    return toPublicKey(curve?.jcaName, x, y)
}

private fun toPublicKey(curveName: String?, xCoordinate: ByteArray?, yCoordinate: ByteArray?): JCEECPublicKey {
    val parameterSpec = ECNamedCurveTable.getParameterSpec(curveName ?: "P-256")
    val x = BigInteger(1, xCoordinate)
    val y = BigInteger(1, yCoordinate)
    val ecPoint = parameterSpec.curve.createPoint(x, y)
    val ecPublicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)
    return JCEECPublicKey("EC", ecPublicKeySpec)
}

fun JsonWebKey.Companion.fromJcaKey(publicKey: ECPublicKey, ecCurve: EcCurve) =
    fromCoordinates(
        EC,
        ecCurve,
        publicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes),
        publicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
    )

fun CoseKey.Companion.fromJcaKey(publicKey: ECPublicKey, ecCurve: CoseEllipticCurve) =
    fromCoordinates(
        EC2,
        ecCurve,
        publicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes),
        publicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
    )

open class JvmEphemeralKeyHolder(private val ecCurve: EcCurve) : EphemeralKeyHolder {

    val keyPair: KeyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(ecCurve.keyLengthBits) }.genKeyPair()

    override fun toPublicJsonWebKey(): JsonWebKey {
        return JsonWebKey.fromJcaKey(keyPair.public as ECPublicKey, ecCurve)!!
    }

}

fun loadDocSigner(str: InputStream): ECPublicKey {
    val factory = KeyFactory.getInstance("EC")
    val pem = PemReader(str.reader()).readPemObject()
    val encoded = pem.content
    val pubKeySpec = X509EncodedKeySpec(encoded)
    return factory.generatePublic(pubKeySpec) as ECPublicKey

}
