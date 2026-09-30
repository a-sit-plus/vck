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
 * Enforces time validity, that the anchor may issue certificates at all, and cryptographic integrity.
 *
 * An anchor that does not assert `BasicConstraints` with `cA` set is skipped, per
 * [RFC 5280, Section 4.2.1.9](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9): its public key
 * "MUST NOT be used to verify certificate signatures". Without that check an end entity certificate that ends
 * up on a trust list -- a document signer rather than its CA, say -- would be able to issue certificates for
 * anything, which is the difference between trusting an issuer and trusting everything it ever signed.
 */
fun X509Certificate.isTrustedBy(
    trustStore: CertificateChain,
    date: Instant = Clock.System.now()
): KmmResult<Success> = catching {
    if (!this.isValidAt(date)) throw Exception("Certificate is not valid at $date")

    val valid = trustStore.filter { it.isValidAt(date) }
    val authorities = valid.filter { it.isCertificateAuthority }
    authorities
        .asSequence()
        .map { it.isIssuerOf(this) }
        .firstOrNull { it.isSuccess }
        ?: throw IllegalArgumentException(
            if (valid.isNotEmpty() && authorities.isEmpty())
                "No valid trust anchor could verify certificate: none of the ${valid.size} anchor(s) valid at " +
                        "$date asserts BasicConstraints with cA set, so none of them may issue certificates"
            else "No valid trust anchor could verify certificate"
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