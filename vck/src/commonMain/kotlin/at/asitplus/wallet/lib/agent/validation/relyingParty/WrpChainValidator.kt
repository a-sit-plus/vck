package at.asitplus.wallet.lib.agent.validation.relyingParty

import at.asitplus.catching
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.etsi.isExpired
import at.asitplus.wallet.lib.etsi.isCertificateAuthority
import at.asitplus.wallet.lib.etsi.isIssuerOf
import at.asitplus.wallet.lib.etsi.isTrustedBy
import at.asitplus.wallet.lib.etsi.isValidAt
import io.github.aakira.napier.Napier
import kotlin.time.Clock

/**
 * Class to verify a certificate chain against trusted roots.
 * Validations:
 *  - Validity periods
 *  - Certificate trust anchors
 *  - Signature chain
 *  - That every certificate issuing another one is a certificate authority
 *
 * Not validated: `pathLenConstraint`, `keyUsage`, and revocation.
 **/

object WrpChainValidator {
    suspend operator fun invoke(
        chain: CertificateChain,
        certificateTrustAnchors: TrustedCertificates
    ) = catching {
        Napier.d("Received chain with ${chain.size} certificate(s).")
        require(chain.isNotEmpty()) { "Certificate chain is empty." }
        val now = Clock.System.now()

        chain.forEach { certificate ->
            require(certificate.isValidAt(now)) {
                if (certificate.isExpired(now)) "Certificate is expired: $certificate"
                else "Certificate is not yet valid: $certificate"
            }
        }

        chain.windowed(size = 2).forEach { (child, issuer) ->
            issuer.isIssuerOf(child).getOrElse { cause ->
                throw IllegalArgumentException("$child is not signed by $issuer", cause)
            }
            // Checked after the signature, so that a structurally broken chain reports that rather than this:
            // a valid signature only says the key was used, RFC 5280 section 4.2.1.9 says whether it was
            // allowed to be. Without this, an end entity certificate anywhere in the chain could vouch for a
            // certificate below it, and only the top of the chain would ever be anchored.
            require(issuer.isCertificateAuthority) {
                "$issuer signed $child but does not assert BasicConstraints with cA set, so it may not issue " +
                        "certificates"
            }
        }

        val trusted = certificateTrustAnchors().toList()
        require(trusted.isNotEmpty()) { "No trusted root certificates configured for request validation." }
        val top = chain.last()
        if (trusted.none { it.encodeToDer().contentEquals(top.encodeToDer()) }) {
            top.isTrustedBy(trusted, now).getOrThrow()
        }
        Napier.d("Chain validation completed (full chain validity enforced).")
        true
    }
}
