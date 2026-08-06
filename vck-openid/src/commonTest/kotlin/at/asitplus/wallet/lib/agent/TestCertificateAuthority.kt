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

/**
 * A certificate authority for tests, i.e. an ephemeral key with a self-signed certificate that can issue
 * certificates for other keys, e.g. a wallet provider or a credential issuer's CA.
 *
 * Copy of the helper in the `vck` tests, as test sources are not shared between modules.
 */
class TestCertificateAuthority(
    private val name: String = "Test CA ${Random.nextInt()}",
    private val key: EphemeralKeyWithoutCert = EphemeralKeyWithoutCert(),
    private val validity: Duration = 5.minutes,
) {
    /** The certificate to put on a trust list. */
    suspend fun certificate(): X509Certificate = certificateFor(name, name, key.publicKey, key)

    /** Key material whose [KeyMaterial.getCertificate] is issued by this authority. */
    suspend fun issue(
        subjectName: String = "Test Issuer ${Random.nextInt()}",
        extensions: List<X509CertificateExtension> = listOf(),
    ): KeyMaterial =
        EphemeralKeyWithoutCert().let {
            KeyWithFixedCert(it, certificateFor(subjectName, name, it.publicKey, key, extensions))
        }

    private suspend fun certificateFor(
        subjectName: String,
        issuerName: String,
        publicKey: CryptoPublicKey,
        issuerKey: KeyMaterial,
        extensions: List<X509CertificateExtension> = listOf(),
    ): X509Certificate {
        val algorithm = issuerKey.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow()
        val notBefore = Clock.System.now().truncateToSeconds()
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

    private fun commonName(value: String) = AttributeTypeAndValue.CommonName(Asn1String.UTF8(value))
}

private class KeyWithFixedCert(
    private val key: EphemeralKeyWithoutCert,
    private val certificate: X509Certificate,
) : KeyMaterial, Signer by key {
    override val identifier: String get() = key.identifier
    override fun getUnderLyingSigner(): Signer = key.getUnderLyingSigner()
    override suspend fun getCertificate(): X509Certificate = certificate
}
