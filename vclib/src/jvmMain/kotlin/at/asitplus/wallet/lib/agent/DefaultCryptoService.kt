package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.jws.EcCurve
import at.asitplus.wallet.lib.jws.JsonWebKey
import at.asitplus.wallet.lib.jws.JweAlgorithm
import at.asitplus.wallet.lib.jws.JweEncryption
import at.asitplus.wallet.lib.jws.JwkType
import at.asitplus.wallet.lib.jws.JwsAlgorithm
import at.asitplus.wallet.lib.jws.JwsExtensions.convertToAsn1Signature
import at.asitplus.wallet.lib.jws.JwsExtensions.ensureSize
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.JCEECPublicKey
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.util.io.pem.PemReader
import java.io.InputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

actual open class DefaultCryptoService : CryptoService {

    private val ecCurve: EcCurve = EcCurve.SECP_256_R_1
    private val keyPair: KeyPair
    private val jsonWebKey: JsonWebKey
    override val keyId: String

    actual constructor() {
        this.keyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(ecCurve.keyLengthBits) }.genKeyPair()
        this.jsonWebKey = JsonWebKey.fromCoordinates(
            JwkType.EC,
            EcCurve.SECP_256_R_1,
            (keyPair.public as ECPublicKey).w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes),
            (keyPair.public as ECPublicKey).w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        )!!
        this.keyId = jsonWebKey.keyId!!
    }

    constructor(keyPair: KeyPair) {
        this.keyPair = keyPair
        this.jsonWebKey = JsonWebKey.fromCoordinates(
            JwkType.EC,
            EcCurve.SECP_256_R_1,
            (keyPair.public as ECPublicKey).w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes),
            (keyPair.public as ECPublicKey).w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        )!!
        this.keyId = jsonWebKey.keyId!!
    }

    override val jwsAlgorithm = JwsAlgorithm.ES256

    override fun toJsonWebKey() = jsonWebKey

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

    override fun extractPublicKeyFromX509Cert(it: ByteArray): JsonWebKey? = try {
        val pubKey = CertificateFactory.getInstance("X.509").generateCertificate(it.inputStream()).publicKey
        if (pubKey is ECPublicKey) JsonWebKey.fromJcaKey(pubKey, EcCurve.SECP_256_R_1) else null
    } catch (e: Throwable) {
        null
    }
}

val JwsAlgorithm.jcaName
    get() = when (this) {
        JwsAlgorithm.ES256 -> "SHA256withECDSA"
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
        EcCurve.SECP_256_R_1 -> "secp256r1"
    }

fun JsonWebKey.getPublicKey(): PublicKey {
    val parameterSpec = ECNamedCurveTable.getParameterSpec("P-256")
    val x = BigInteger(1, x)
    val y = BigInteger(1, y)
    val ecPoint = parameterSpec.curve.createPoint(x, y)
    val ecPublicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)
    return JCEECPublicKey("EC", ecPublicKeySpec)
}


fun JsonWebKey.Companion.fromJcaKey(publicKey: ECPublicKey, ecCurve: EcCurve) =
    fromCoordinates(
        JwkType.EC,
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
