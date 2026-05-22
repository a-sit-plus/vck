package at.asitplus.wallet.lib

import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.requireSupported
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Verifies if this leaf certificate is directly signed and trusted by any anchor in the [trustStore].
 * Enforces strict timeliness, cryptographic integrity, and anchor constraints.
 */
fun X509Certificate.isDirectlyTrustedBy(
    trustStore: CertificateChain,
    date: Instant = Clock.System.now()
): Boolean {
    if (!this.isValidAt(date)) return false

    return trustStore
        .filter { anchor -> anchor.tbsCertificate.subjectName == this.tbsCertificate.issuerName }
        .any { anchor ->
            anchor.isValidAt(date) && anchor.isIssuerOf(this)
        }
}

/**
 * Checks whether this certificate has expired at the specified [date].
 *
 * @return `true` if the certificate is expired, `false` otherwise.
 */
fun X509Certificate.isExpired(date: Instant = Clock.System.now()): Boolean =
    Instant.fromEpochSeconds(date.epochSeconds) > tbsCertificate.validUntil.instant

/**
 * Checks whether this certificate is not yet valid at the specified [date].
 *
 * @return `true` if the certificate is not yet valid, `false` otherwise.
 */
fun X509Certificate.isNotYetValid(date: Instant = Clock.System.now()): Boolean =
    Instant.fromEpochSeconds(date.epochSeconds) < tbsCertificate.validFrom.instant


/**
 * Checks whether this certificate is valid at the specified [date].
 */
fun X509Certificate.isValidAt(date: Instant = Clock.System.now()): Boolean = !(isExpired(date) || isNotYetValid(date))

fun X509Certificate.isIssuerOf(cert: X509Certificate): Boolean {
    val verifier = (cert.signatureAlgorithm.requireSupported() as X509SignatureAlgorithm).verifierFor(this.decodedPublicKey.getOrThrow()).getOrElse { return false }
    val signatureValid = verifier.verify(
        cert.tbsCertificate.encodeToDer(),
        cert.decodedSignature.getOrThrow()
    ).isSuccess

    val issuerName = cert.tbsCertificate.issuerName
    return signatureValid && issuerName == this.tbsCertificate.subjectName
}