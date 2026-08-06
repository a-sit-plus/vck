package at.asitplus.wallet.lib.agent

import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.sign.Signer
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * A certificate authority for tests, i.e. an ephemeral key with a self-signed certificate that can issue
 * certificates for other keys.
 *
 * In contrast to [X509Certificate.generateSelfSignedCertificate], which hardcodes both the issuer and the
 * subject name to `Default`, this sets distinct names, so that name chaining in
 * [at.asitplus.wallet.lib.etsi.isTrustedBy] is actually exercised.
 */
class TestCertificateAuthority(
    val name: String = "Test CA ${Random.nextInt()}",
    private val key: EphemeralKeyWithoutCert = EphemeralKeyWithoutCert(),
    private val validity: Duration = 5.minutes,
) {
    /** The certificate to put on a trust list. */
    suspend fun certificate(): X509Certificate =
        certificateFor(key.publicKey, name, name, key, validity)

    /** Key material whose [KeyMaterial.getCertificate] is issued by this authority, for use as an issuer key. */
    suspend fun issue(
        subjectName: String = "Test Issuer ${Random.nextInt()}",
        validity: Duration = this.validity,
        validFrom: Instant = Clock.System.now(),
        key: EphemeralKeyWithoutCert = EphemeralKeyWithoutCert(),
        extensions: List<X509CertificateExtension> = listOf(),
    ): KeyMaterial = KeyWithFixedCert(
        key = key,
        certificate = certificateFor(key.publicKey, subjectName, name, this.key, validity, validFrom, extensions),
    )

    companion object {
        /** Builds a certificate for [publicKey], signed by [issuerKey]. */
        suspend fun certificateFor(
            publicKey: CryptoPublicKey,
            subjectName: String,
            issuerName: String,
            issuerKey: KeyMaterial,
            validity: Duration = 5.minutes,
            validFrom: Instant = Clock.System.now(),
            extensions: List<X509CertificateExtension> = listOf(),
        ): X509Certificate {
            val algorithm = issuerKey.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow()
            val notBefore = validFrom.truncateToSeconds()
            val tbsCertificate = TbsCertificate(
                version = 2,
                serialNumber = Random.nextBytes(8),
                issuerName = listOf(RelativeDistinguishedName(commonName(issuerName))),
                subjectName = listOf(RelativeDistinguishedName(commonName(subjectName))),
                validFrom = Asn1Time(notBefore),
                validUntil = Asn1Time((notBefore + validity).truncateToSeconds()),
                signatureAlgorithm = algorithm,
                publicKey = publicKey,
                extensions = extensions,
            )
            val signature = issuerKey.sign(tbsCertificate.encodeToDer()).asKmmResult().getOrThrow()
            return X509Certificate(tbsCertificate, algorithm, signature)
        }

        private fun commonName(value: String) =
            AttributeTypeAndValue.CommonName(Asn1String.UTF8(value))
    }
}

/** Key material presenting a certificate built by [TestCertificateAuthority.certificateFor]. */
class KeyWithFixedCert(
    private val key: EphemeralKeyWithoutCert,
    private val certificate: X509Certificate,
) : KeyMaterial, Signer by key {
    override val identifier: String get() = key.identifier
    override fun getUnderLyingSigner(): Signer = key.getUnderLyingSigner()
    override suspend fun getCertificate(): X509Certificate = certificate
}

/** A key with a self-signed certificate, with control over its validity window, unlike [EphemeralKeyWithSelfSignedCert]. */
suspend fun selfSignedKey(
    name: String = "Self Signed ${Random.nextInt()}",
    validity: Duration = 5.minutes,
    validFrom: Instant = Clock.System.now(),
): KeyMaterial = EphemeralKeyWithoutCert().let { key ->
    KeyWithFixedCert(
        key = key,
        certificate = TestCertificateAuthority.certificateFor(
            key.publicKey, name, name, key, validity, validFrom
        ),
    )
}
