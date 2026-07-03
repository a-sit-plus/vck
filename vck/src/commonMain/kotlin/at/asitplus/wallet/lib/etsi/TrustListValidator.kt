package at.asitplus.wallet.lib.etsi

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * A success identity object to avoid KmmResult<Unit> footguns.
 */
data object Success

/**
 * Verifies if this certificate is directly signed and trusted by any anchor in the [trustStore].
 * Enforces time validity, cryptographic integrity
 */
fun X509Certificate.isTrustedBy(
    trustStore: CertificateChain,
    date: Instant = Clock.System.now()
): KmmResult<Success> = catching {
    if (!this.isValidAt(date)) throw Exception("Certificate is not valid at $date")

    trustStore
        .asSequence()
        .filter { it.isValidAt(date) }
        .map { it.isIssuerOf(this) }
        .firstOrNull { it.isSuccess }
        ?: throw IllegalArgumentException(
            "No valid trust anchor could verify certificate"
        )
    Success
}

/**
 * Checks whether this certificate has expired at the specified [date].
 * @return `true` if the certificate is expired, `false` otherwise.
 */
fun X509Certificate.isExpired(date: Instant = Clock.System.now()): Boolean =
    date > tbsCertificate.validUntil.instant

/**
 * Checks whether this certificate is not yet valid at the specified [date].
 * @return `true` if the certificate is not yet valid, `false` otherwise.
 */
fun X509Certificate.isNotYetValid(date: Instant = Clock.System.now()): Boolean =
    date < tbsCertificate.validFrom.instant


/**
 * Checks whether this certificate is valid at the specified [date].
 */
fun X509Certificate.isValidAt(date: Instant = Clock.System.now()): Boolean = !(isExpired(date) || isNotYetValid(date))

/**
 * Verifies that this certificate is the issuer of the given [cert].
 */
fun X509Certificate.isIssuerOf(cert: X509Certificate): KmmResult<Unit> = catching {
    if (cert.tbsCertificate.issuerName != this.tbsCertificate.subjectName) throw Exception("Subject of issuer cert and issuer of child certificate mismatch.")

    if (cert.tbsCertificate.issuerUniqueID != this.tbsCertificate.subjectUniqueID) throw Exception("UID of issuer cert and UID of issuer in child certificate mismatch.")

    val verifier = (cert.signatureAlgorithm as X509SignatureAlgorithm).verifierFor(this.decodedPublicKey.getOrThrow()).getOrThrow()
    verifier.verify(
        cert.tbsCertificate.encodeToDer(),
        cert.decodedSignature.getOrThrow()
    ).getOrThrow()
}