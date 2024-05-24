package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.*
import at.asitplus.crypto.datatypes.EcCurve.SECP_256_R_1
import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.cose.CoseKey
import at.asitplus.crypto.datatypes.cose.toCoseAlgorithm
import at.asitplus.crypto.datatypes.cose.toCoseKey
import at.asitplus.crypto.datatypes.jws.*
import at.asitplus.crypto.datatypes.pki.*
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.JCEECPublicKey
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.*
import java.security.cert.Certificate
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.absoluteValue
import kotlin.random.Random


actual open class DefaultCryptoService : CryptoService {

    private val privateKey: PrivateKey

    final override val algorithm: CryptoAlgorithm

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
        this.algorithm = CryptoAlgorithm.ES256
        this.publicKey = CryptoPublicKey.fromJcaPublicKey(keyPair.public).getOrThrow()
        this.jsonWebKey = publicKey.toJsonWebKey()
        this.coseKey = publicKey.toCoseKey(algorithm.toCoseAlgorithm()).getOrThrow()
        this.certificate = X509Certificate.generateSelfSignedCertificate(this)
    }

    /**
     * Constructor which allows all public keys implemented in `KMP-Crypto`
     * Because RSA needs the algorithm parameter to be useful (as it cannot be inferred from the key)
     * it's mandatory
     * Also used for custom certificates
     */
    constructor(keyPair: KeyPair, algorithm: CryptoAlgorithm, certificate: Certificate? = null) {
        this.privateKey = keyPair.private
        this.algorithm = algorithm
        this.publicKey = CryptoPublicKey.fromJcaPublicKey(keyPair.public).getOrThrow()
        this.jsonWebKey = publicKey.toJsonWebKey()
        this.coseKey = publicKey.toCoseKey(algorithm.toCoseAlgorithm()).getOrThrow()
        this.certificate = certificate?.let { X509Certificate.decodeFromDer(it.encoded) }
            ?: X509Certificate.generateSelfSignedCertificate(this)
    }

    override suspend fun sign(input: ByteArray): KmmResult<CryptoSignature> = runCatching {
        val sig = Signature.getInstance(algorithm.jcaName).apply {
            this@DefaultCryptoService.algorithm.jcaParams?.let { setParameter(it) }
            initSign(privateKey)
            update(input)
        }.sign()
        CryptoSignature.parseFromJca(sig, algorithm)
    }.wrap()

    override fun encrypt(
        key: ByteArray, iv: ByteArray, aad: ByteArray, input: ByteArray, algorithm: JweEncryption
    ): KmmResult<AuthenticatedCiphertext> = runCatching {
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
    ): KmmResult<ByteArray> = runCatching {
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
    ): KmmResult<ByteArray> = runCatching {
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
    ): KmmResult<ByteArray> = runCatching {
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

    override fun messageDigest(input: ByteArray, digest: Digest): KmmResult<ByteArray> = runCatching {
        MessageDigest.getInstance(digest.jcaName).digest(input)
    }.wrap()

}

actual open class DefaultVerifierCryptoService : VerifierCryptoService {

    override val supportedAlgorithms: List<CryptoAlgorithm> = CryptoAlgorithm.entries.filter { it.isEc }

    override fun verify(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: CryptoAlgorithm,
        publicKey: CryptoPublicKey,
    ): KmmResult<Boolean> =
        runCatching {
            Signature.getInstance(algorithm.jcaName).apply {
                algorithm.jcaParams?.let { setParameter(it) }
                initVerify(publicKey.getJcaPublicKey().getOrThrow())
                update(input)
            }.verify(signature.jcaSignatureBytes)
        }.wrap()
}

open class JvmEphemeralKeyHolder(private val ecCurve: EcCurve) : EphemeralKeyHolder {

    val keyPair: KeyPair =
        KeyPairGenerator.getInstance("EC").also { it.initialize(ecCurve.keyLengthBits.toInt()) }.genKeyPair()

    override val publicJsonWebKey: JsonWebKey? by lazy {
        CryptoPublicKey.fromJcaPublicKey(keyPair.public).map { it.toJsonWebKey() }.getOrNull()
    }

}

fun X509Certificate.Companion.generateSelfSignedCertificate(
    cryptoService: CryptoService,
    commonName: String = "DefaultCryptoService"
): X509Certificate {
    val serialNumber: BigInteger = BigInteger.valueOf(Random.nextLong().absoluteValue)
    val notBeforeDate = Clock.System.now()
    val notAfterDate = notBeforeDate.plus(30, DateTimeUnit.SECOND)
    val tbsCertificate = TbsCertificate(
        version = 2,
        serialNumber = serialNumber.toByteArray(),
        issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
        validFrom = Asn1Time(notBeforeDate),
        validUntil = Asn1Time(notAfterDate),
        signatureAlgorithm = cryptoService.algorithm,
        subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
        publicKey = cryptoService.publicKey,
        extensions = listOf(X509CertificateExtension(
            KnownOIDs.subjectAltName_2_5_29_17,
            critical = false,
            Asn1EncapsulatingOctetString(listOf(
                asn1Sequence {
                    append(
                        Asn1Primitive(
                            SubjectAltNameImplicitTags.dNSName,
                            Asn1String.UTF8("example.com").encodeToTlv().content
                        )
                    )
                }
            ))))
    )
    val signature = runBlocking {
        runCatching { tbsCertificate.encodeToDer() }
            .wrap()
            .transform { cryptoService.sign(it) }
            .getOrThrow()
    }
    return X509Certificate(tbsCertificate, cryptoService.algorithm, signature)
}