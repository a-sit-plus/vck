package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.*
import at.asitplus.crypto.datatypes.EcCurve.SECP_256_R_1
import at.asitplus.crypto.datatypes.asn1.Asn1String
import at.asitplus.crypto.datatypes.asn1.Asn1Time
import at.asitplus.crypto.datatypes.cose.CoseKey
import at.asitplus.crypto.datatypes.cose.toCoseAlgorithm
import at.asitplus.crypto.datatypes.cose.toCoseKey
import at.asitplus.crypto.datatypes.jws.*
import at.asitplus.crypto.datatypes.pki.DistinguishedName
import at.asitplus.crypto.datatypes.pki.TbsCertificate
import at.asitplus.crypto.datatypes.pki.X509Certificate
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.toKotlinInstant
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.JCEECPublicKey
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.*
import java.security.cert.Certificate
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

    private val privateKey: PrivateKey

    final override val algorithm: JwsAlgorithm

    final override val publicKey: CryptoPublicKey

    final override val certificate: X509Certificate

    final override val jsonWebKey: JsonWebKey

    final override val coseKey: CoseKey

    /**
     * Default constructor without arguments is ES256
     */
    actual constructor() {
        val keyPair =
            KeyPairGenerator.getInstance("EC").also { it.initialize(SECP_256_R_1.keyLengthBits.toInt()) }.genKeyPair()
        this.privateKey = keyPair.private
        this.algorithm = JwsAlgorithm.ES256
        this.publicKey = CryptoPublicKey.fromJcaPublicKey(keyPair.public).getOrThrow()
        this.jsonWebKey = publicKey.toJsonWebKey().getOrThrow()
        this.coseKey = publicKey.toCoseKey(algorithm.toCoseAlgorithm()).getOrThrow()
        this.certificate = generateSelfSignedCertificate()
    }

    /**
     * Constructor which allows all public keys implemented in `KMP-Crypto`
     * Because RSA needs the algorithm parameter to be useful (as it cannot be inferred from the key)
     * it's mandatory
     * Also used for non-self-signed certificates
     */
    constructor(keyPair: KeyPair, algorithm: JwsAlgorithm, certificate: Certificate? = null) {
        this.privateKey = keyPair.private
        this.algorithm = algorithm
        this.publicKey = CryptoPublicKey.fromJcaPublicKey(keyPair.public).getOrThrow()
        this.jsonWebKey = publicKey.toJsonWebKey().getOrThrow()
        this.coseKey = publicKey.toCoseKey(algorithm.toCoseAlgorithm()).getOrThrow()
        this.certificate =
            certificate?.let { X509Certificate.decodeFromDer(it.encoded) } ?: generateSelfSignedCertificate()
    }

//    private fun generateSelfSignedCertificate(): ByteArray {
//        val notBeforeDate = Date.from(Instant.now())
//        val notAfterDate = Date.from(Instant.now().plusSeconds(30.days.inWholeSeconds))
//        val serialNumber: BigInteger = BigInteger.valueOf(Random.nextLong().absoluteValue)
//        val issuer = X500Name("CN=DefaultCryptoService")
//        val builder = X509v3CertificateBuilder(
//            /* issuer = */ issuer,
//            /* serial = */ serialNumber,
//            /* notBefore = */ notBeforeDate,
//            /* notAfter = */ notAfterDate,
//            /* subject = */ issuer,
//            /* publicKeyInfo = */ SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
//        )
//        val contentSigner: ContentSigner = JcaContentSignerBuilder(algorithm.jcaName).build(keyPair.private)
//        val certificateHolder = builder.build(contentSigner)
//        return certificateHolder.encoded
//    }

    private fun generateSelfSignedCertificate(): X509Certificate {
        val serialNumber: BigInteger = BigInteger.valueOf(Random.nextLong().absoluteValue)
        val commonName = "DefaultCryptoService"
        val notBeforeDate = Date.from(Instant.now())
        val notAfterDate = Date.from(Instant.now().plusSeconds(30.days.inWholeSeconds))
        val tbsCertificate = TbsCertificate(
            version = 2,
            serialNumber = serialNumber.toByteArray(),
            issuerName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
            validFrom = Asn1Time(notBeforeDate.toInstant().toKotlinInstant()),
            validUntil = Asn1Time(notAfterDate.toInstant().toKotlinInstant()),
            signatureAlgorithm = algorithm,
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
            publicKey = publicKey
        )
        val signature =
            runBlocking {
                runCatching { tbsCertificate.encodeToDer() }
                    .wrap()
                    .transform { sign(it) }
                    .getOrThrow()
            }
        return X509Certificate(tbsCertificate, algorithm, signature)
    }

    override suspend fun sign(input: ByteArray): KmmResult<CryptoSignature> =
        runCatching {
            Signature.getInstance(algorithm.jcaName).apply {
                initSign(privateKey)
                update(input)
            }.sign()
        }.wrap().map { CryptoSignature.fromDerEncoded(it, algorithm) }

    override fun encrypt(
        key: ByteArray, iv: ByteArray, aad: ByteArray, input: ByteArray, algorithm: JweEncryption
    ): KmmResult<AuthenticatedCiphertext> =
        runCatching {
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

            AuthenticatedCiphertext(ciphertext, authtag)
        }.wrap()


    override suspend fun decrypt(
        key: ByteArray, iv: ByteArray, aad: ByteArray, input: ByteArray, authTag: ByteArray, algorithm: JweEncryption
    ): KmmResult<ByteArray> =
        runCatching {
            Cipher.getInstance(algorithm.jcaName).also {
                it.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpecName),
                    GCMParameterSpec(algorithm.ivLengthBits, iv)
                )
                it.updateAAD(aad)
            }.doFinal(input + authTag)
        }.wrap()

    override fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder, recipientKey: JsonWebKey, algorithm: JweAlgorithm
    ): KmmResult<ByteArray> =
        runCatching {
            require(ephemeralKey is JvmEphemeralKeyHolder) { "JVM Type expected" }

            KeyAgreement.getInstance(algorithm.jcaName).also {
                it.init(ephemeralKey.keyPair.private)
                it.doPhase(
                    recipientKey.toCryptoPublicKey().transform { it1 -> it1.getJcaPublicKey() }.getOrThrow(), true
                )
            }.generateSecret()
        }.wrap()

    override fun performKeyAgreement(
        ephemeralKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray> =
        runCatching {
            val parameterSpec = ECNamedCurveTable.getParameterSpec(ephemeralKey.curve?.jcaName)
            val ecPoint =
                parameterSpec.curve.validatePoint(BigInteger(1, ephemeralKey.x), BigInteger(1, ephemeralKey.y))
            val ecPublicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)
            val publicKey = JCEECPublicKey("EC", ecPublicKeySpec)

            KeyAgreement.getInstance(algorithm.jcaName).also {
                it.init(privateKey)
                it.doPhase(publicKey, true)
            }.generateSecret()
        }.wrap()

    override fun generateEphemeralKeyPair(ecCurve: EcCurve): KmmResult<EphemeralKeyHolder> =
        KmmResult.success(JvmEphemeralKeyHolder(ecCurve))

    override fun messageDigest(input: ByteArray, digest: Digest): KmmResult<ByteArray> =
        runCatching {
            MessageDigest.getInstance(digest.jcaName).digest(input)
        }.wrap()

}

actual open class DefaultVerifierCryptoService : VerifierCryptoService {
    override fun verify(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: JwsAlgorithm,
        publicKey: CryptoPublicKey,
    ): KmmResult<Boolean> =
        runCatching {
            Signature.getInstance(algorithm.jcaName).apply {
                initVerify(publicKey.getJcaPublicKey().getOrThrow())
                update(input)
            }.verify(signature.derEncoded)
        }.wrap()
}

open class JvmEphemeralKeyHolder(private val ecCurve: EcCurve) : EphemeralKeyHolder {

    val keyPair: KeyPair =
        KeyPairGenerator.getInstance("EC").also { it.initialize(ecCurve.keyLengthBits.toInt()) }.genKeyPair()

    override val publicJsonWebKey by lazy {
        CryptoPublicKey.fromJcaPublicKey(keyPair.public).transform { it.toJsonWebKey() }.getOrNull()
    }

}

//fun loadDocSigner(str: InputStream): ECPublicKey {
//    val factory = KeyFactory.getInstance("EC")
//    val pem = PemReader(str.reader()).readPemObject()
//    val encoded = pem.content
//    val pubKeySpec = X509EncodedKeySpec(encoded)
//    return factory.generatePublic(pubKeySpec) as ECPublicKey
//
//}
