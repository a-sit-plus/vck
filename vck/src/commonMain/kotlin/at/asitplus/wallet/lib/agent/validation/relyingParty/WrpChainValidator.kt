package at.asitplus.wallet.lib.agent.validation.relyingParty

import at.asitplus.catching
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.root
import at.asitplus.wallet.lib.etsi.isIssuerOf
import io.github.aakira.napier.Napier
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Class to verify a certificate chain against trusted roots.
 * Validations:
 *  - Validity periods
 *  - Certificate trust anchors
 *  - Signature chain
 **/
object WrpChainValidator {
    private val timeLeeway: Duration = 5.minutes

    operator fun invoke(chain: CertificateChain, certificateTrustAnchors: List<X509Certificate>) = catching {
        Napier.d("Received chain with ${chain.size} certificate(s).")

        validateValidityPeriods(chain)

        val signatureChainOk = validateSignatures(chain)
        val trustedRootOk = validateTrustedRoot(chain, certificateTrustAnchors)
        if (!signatureChainOk || !trustedRootOk) {
            throw Throwable("Chain validation failed.")
        }

        Napier.d("Chain validation completed (full chain validity enforced).")
        true
    }

    private fun validateValidityPeriods(chain: CertificateChain) = run {
        val now = Clock.System.now()
        chain.forEach { certificate ->
            Napier.d("Validate validity periods of $certificate")
            val validFrom = certificate.tbsCertificate.validFrom.instant
            val validUntil = certificate.tbsCertificate.validUntil.instant
            Napier.d("Certificate validity=$validFrom .. $validUntil")
            if (validFrom > (now + timeLeeway)) {
                throw Throwable("Certificate is not yet valid (valid from $validFrom).")
            }
            if (validUntil < (now - timeLeeway)) {
                throw Throwable("Certificate is expired (valid until $validUntil).")
            }
        }
        true
    }

    private fun validateSignatures(chain: CertificateChain) = run {
        if (chain.size == 1) {
            Napier.d("Chain has only leaf certificate; issuer signature check delegated to trust anchor.")
            return@run true
        }

        chain.windowed(size = 2, step = 1).forEach { (child, issuer) ->
            if (!isCertificateSignedBy(child, issuer)) {
                throw Throwable("$child is not signed by $issuer")
            }
        }

        true
    }

    private fun validateTrustedRoot(chain: CertificateChain, certificateTrustAnchors: List<X509Certificate>) =
        run {
            if (certificateTrustAnchors.isEmpty()) {
                throw Throwable("No trusted root certificates configured for request validation.")
            }
            Napier.d("Checking top certificate against ${certificateTrustAnchors.size} trusted root certificate(s).")

            val anchored = certificateTrustAnchors.any { trustedRoot ->
                val sameCertificate = areSameCertificate(chain.root, trustedRoot).getOrThrow()
                val signedByTrustedRoot = !sameCertificate && isCertificateSignedBy(chain.root, trustedRoot)
                if (sameCertificate || signedByTrustedRoot) {
                    Napier.d(
                        "trust anchor matched trusted root (${trustedRoot.shortFingerprint()}), " + "mode=${if (sameCertificate) "exact" else "signed"}."
                    )
                }
                sameCertificate || signedByTrustedRoot
            }

            if (!anchored) {
                throw Throwable(
                    "is not anchored to a configured trusted root certificate. " + "x5cTop=${
                        chain.root.shortFingerprint()
                    }"
                )
            }

            Napier.d("x5c chain anchored to trusted roots.")
            true
        }

    private fun isCertificateSignedBy(certificate: X509Certificate, issuer: X509Certificate): Boolean =
        issuer.isIssuerOf(certificate).isSuccess

    private fun areSameCertificate(first: X509Certificate, second: X509Certificate) =
        catching { first.encodeToDer().contentEquals(second.encodeToDer()) }
}
