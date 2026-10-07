package at.asitplus.wallet.lib.etsi

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.sign.verifierFor
import at.asitplus.signum.indispensable.sign.verify
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
suspend fun Certificate.isTrustedBy(
    trustStore: CertificateChain,
    date: Instant = Clock.System.now()
): KmmResult<Success> = catching {
    if (!this.isValidAt(date)) throw Exception("Certificate is not valid at $date")

    val valid = trustStore.filter { it.isValidAt(date) }
    val authorities = valid.filter { it.isCertificateAuthority }
    authorities.firstOrNull { it.isIssuerOf(this).isSuccess }
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
fun Certificate.isExpired(date: Instant = Clock.System.now()): Boolean =
    date > tbsCertificate.validUntil

/**
 * Checks whether this certificate is not yet valid at the specified [date].
 * @return `true` if the certificate is not yet valid, `false` otherwise.
 */
fun Certificate.isNotYetValid(date: Instant = Clock.System.now()): Boolean =
    date < tbsCertificate.validFrom


/**
 * Checks whether this certificate is valid at the specified [date].
 */
fun Certificate.isValidAt(date: Instant = Clock.System.now()): Boolean = !(isExpired(date) || isNotYetValid(date))

/**
 * Verifies that this certificate is the issuer of the given [cert].
 */
suspend fun Certificate.isIssuerOf(cert: Certificate): KmmResult<Unit> = catching {
    if (cert.tbsCertificate.issuerName != this.tbsCertificate.subjectName) throw Exception("Subject of issuer cert and issuer of child certificate mismatch.")

    if (cert.tbsCertificate.issuerUniqueID != this.tbsCertificate.subjectUniqueID) throw Exception("UID of issuer cert and UID of issuer in child certificate mismatch.")

    val verifier = cert.signatureAlgorithm.verifierFor(this.publicKey)
    verifier.verify(cert)
    Unit
}
