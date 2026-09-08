package at.asitplus.wallet.lib.agent.validation.relyingParty

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.root
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpChainValidator.Constants.LOG_TAG
import at.asitplus.wallet.lib.etsi.isIssuerOf
import io.github.aakira.napier.Napier
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

object WrpChainValidator {
    private val timeLeeway: Duration = 5.minutes
    fun validateChain(chain: CertificateChain, certificateTrustAnchors: List<X509Certificate>): Boolean {
        Napier.d("Received chain with ${chain.size} certificate(s).", tag = LOG_TAG)

        if (!validateValidityPeriods(chain)) {
            return false
        }

        val signatureChainOk = validateSignatures(chain)
        val trustedRootOk = validateTrustedRoot(chain, certificateTrustAnchors)
        if (!signatureChainOk || !trustedRootOk) {
            Napier.w("Chain validation failed.", tag = LOG_TAG)
            return false
        }

        Napier.d("Chain validation completed (full chain validity enforced).", tag = LOG_TAG)
        return true
    }

    private fun validateValidityPeriods(chain: CertificateChain): Boolean {
        val now = Clock.System.now()
        chain.forEach { certificate ->
            Napier.d("Validate validity periods of $certificate")
            val validFrom = certificate.tbsCertificate.validFrom.instant
            val validUntil = certificate.tbsCertificate.validUntil.instant
            Napier.d("Certificate validity=$validFrom .. $validUntil", tag = LOG_TAG)
            if (validFrom > (now + timeLeeway)) {
                Napier.w("Certificate is not yet valid (valid from $validFrom).", tag = LOG_TAG)
                return false
            }
            if (validUntil < (now - timeLeeway)) {
                Napier.w("Certificate is expired (valid until $validUntil).", tag = LOG_TAG)
                return false
            }
        }
        return true
    }

    private fun validateSignatures(chain: CertificateChain): Boolean {
        if (chain.size == 1) {
            Napier.d(
                "Chain has only leaf certificate; issuer signature check delegated to trust anchor.", tag = LOG_TAG
            )
            return true
        }

        chain.windowed(size = 2, step = 1).forEach { (child, issuer) ->
            if (!isCertificateSignedBy(child, issuer)) {
                Napier.w("$child is not signed by $issuer")
                return false
            }
        }

        return true
    }

    private fun validateTrustedRoot(chain: CertificateChain, certificateTrustAnchors: List<X509Certificate>): Boolean {
        if (certificateTrustAnchors.isEmpty()) {
            Napier.e("No trusted root certificates configured for request validation.", tag = LOG_TAG)
            return false
        }
        Napier.d(
            "Checking top certificate against ${certificateTrustAnchors.size} trusted root certificate(s).",
            tag = LOG_TAG
        )

        val anchored = certificateTrustAnchors.any { trustedRoot ->
            val sameCertificate = areSameCertificate(chain.root, trustedRoot)
            val signedByTrustedRoot = !sameCertificate && isCertificateSignedBy(chain.root, trustedRoot)
            if (sameCertificate || signedByTrustedRoot) {
                Napier.d(
                    "trust anchor matched trusted root (${trustedRoot.shortFingerprint()}), " + "mode=${if (sameCertificate) "exact" else "signed"}.",
                    tag = LOG_TAG
                )
            }
            sameCertificate || signedByTrustedRoot
        }

        if (!anchored) {
            Napier.e(
                "is not anchored to a configured trusted root certificate. " + "x5cTop=${
                    chain.root.shortFingerprint()
                }", tag = LOG_TAG
            )
            return false
        }

        Napier.d("x5c chain anchored to trusted roots.", tag = LOG_TAG)
        return true
    }

    private fun isCertificateSignedBy(certificate: X509Certificate, issuer: X509Certificate): Boolean =
        issuer.isIssuerOf(certificate).isSuccess

    private fun areSameCertificate(first: X509Certificate, second: X509Certificate): Boolean =
        catchingUnwrapped { first.encodeToDer().contentEquals(second.encodeToDer()) }.getOrDefault(false)


    private object Constants {
        val LOG_TAG = "WrpChainValidator"
    }
}
