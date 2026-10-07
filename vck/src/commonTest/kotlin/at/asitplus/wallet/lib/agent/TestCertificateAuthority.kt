package at.asitplus.wallet.lib.agent

import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.X500Name
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.indispensable.encodeToDer
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.basicConstraints_2_5_29_19
import at.asitplus.awesn1.Asn1String
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.sign.signature
import at.asitplus.signum.indispensable.sign.Signer
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * A certificate authority for tests, i.e. an ephemeral key with a self-signed certificate that can issue
 * certificates for other keys.
 *
 * In contrast to [Certificate.generateSelfSignedCertificate], which hardcodes both the issuer and the
 * subject name to `Default`, this sets distinct names, so that name chaining in
 * [at.asitplus.wallet.lib.etsi.isTrustedBy] is actually exercised.
 */
class TestCertificateAuthority private constructor(
    val name: String = "Test CA ${Random.nextInt()}",
    private val key: EphemeralKeyWithoutCert = EphemeralKeyWithoutCert(),
    private val validity: Duration = 5.minutes,
    /** The certificate to put on a trust list. */
    val certificate: Certificate,
) {

    /** Key material whose [KeyMaterial.getCertificate] is issued by this authority, for use as an issuer key. */
    suspend fun issue(
        subjectName: String = "Test Issuer ${Random.nextInt()}",
        validity: Duration = this.validity,
        validFrom: Instant = Clock.System.now(),
        key: EphemeralKeyWithoutCert = EphemeralKeyWithoutCert(),
        extensions: List<CertificateExtension> = listOf(),
        /**
         * Whether the issued certificate may itself issue certificates, i.e. whether it asserts
         * `BasicConstraints` with `cA` set. Defaults to `false`, because an issued certificate is an end entity
         * unless it is meant to be an intermediate; set it for a certificate that signs another one.
         */
        certificateAuthority: Boolean = false,
        /** `pathLenConstraint` of [certificateAuthority], omitted when `null`. */
        pathLength: Int? = null,
    ): KeyMaterial = KeyWithFixedCert(
        key = key,
        certificate = certificateFor(
            publicKey = key.publicKey,
            subjectName = subjectName,
            issuerName = name,
            issuerKey = this.key,
            validity = validity,
            validFrom = validFrom,
            extensions = if (certificateAuthority) extensions + basicConstraintsCa(pathLength) else extensions,
        ),
    )

    companion object {
        /** Builds a certificate for [publicKey], signed by [issuerKey]. */
        internal suspend fun certificateFor(
            publicKey: CryptoPublicKey,
            subjectName: String,
            issuerName: String,
            issuerKey: KeyMaterial,
            validity: Duration = 5.minutes,
            validFrom: Instant = Clock.System.now(),
            extensions: List<CertificateExtension> = listOf(),
        ): Certificate {
            val algorithm = issuerKey.signatureAlgorithm
            val notBefore = validFrom.truncateToSeconds()
            val tbsCertificate = TbsCertificate(
                serialNumber = Asn1Integer.fromUnsignedByteArray(Random.nextBytes(8)),
                issuerName = X500Name(listOf(RelativeDistinguishedName(commonName(issuerName)))),
                subjectName = X500Name(listOf(RelativeDistinguishedName(commonName(subjectName)))),
                validFrom = notBefore,
                validUntil = (notBefore + validity).truncateToSeconds(),
                signatureAlgorithm = algorithm,
                publicKey = publicKey,
                extensions = extensions,
            )
            val signature = issuerKey.sign(tbsCertificate.encodeToDer()).signature
            return Certificate(tbsCertificate, signature)
        }

        private fun commonName(value: String) =
            X500AttributeTypeAndValue.CommonName(Asn1String.UTF8(value))

        suspend operator fun invoke(
            name: String = "Test CA ${Random.nextInt()}",
            key: EphemeralKeyWithoutCert = EphemeralKeyWithoutCert(),
            validity: Duration = 5.minutes,
            /**
             * Whether this authority's own certificate asserts `BasicConstraints` with `cA` set. Set to `false`
             * to build an authority that can sign certificates but may not be trusted to have issued them.
             */
            certificateAuthority: Boolean = true,
            /** `pathLenConstraint` of [certificateAuthority], omitted when `null`. */
            pathLength: Int? = null,
        ) = TestCertificateAuthority(
            name = name,
            key = key,
            validity = validity,
            certificate = certificateFor(
                publicKey = key.publicKey,
                subjectName = name,
                issuerName = name,
                issuerKey = key,
                validity = validity,
                extensions = if (certificateAuthority) listOf(basicConstraintsCa(pathLength)) else listOf(),
            )
        )
    }

}

/** Key material presenting a certificate built by [TestCertificateAuthority.certificateFor]. */
class KeyWithFixedCert(
    private val key: EphemeralKeyWithoutCert,
    private val certificate: Certificate,
) : KeyMaterial, Signer by key {
    override val identifier: String get() = key.identifier
    override fun getUnderLyingSigner(): Signer = key.getUnderLyingSigner()
    override suspend fun getCertificate(): Certificate = certificate
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

/**
 * `BasicConstraints` marking a certificate as a certificate authority, i.e.
 * `SEQUENCE { cA BOOLEAN TRUE }`, see [RFC 5280, Section 4.2.1.9](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9).
 *
 * Without it [at.asitplus.wallet.lib.etsi.isTrustedBy] refuses to let the certificate issue anything, so a test
 * authority that omitted this would be rejected as a trust anchor.
 */
private fun basicConstraintsCa(pathLength: Int? = null) = CertificateExtension(
    oid = KnownOIDs.basicConstraints_2_5_29_19,
    critical = true,
    value = Asn1EncapsulatingOctetString(listOf(Asn1.Sequence {
        +Asn1.Bool(true)
        pathLength?.let { +Asn1.Int(it) }
    })),
)
