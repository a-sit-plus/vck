package at.asitplus.wallet.lib.agent.validation.relyingParty

import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.etsi.isCertificateAuthority
import at.asitplus.wallet.lib.etsi.isExpired
import at.asitplus.wallet.lib.etsi.isIssuerOf
import at.asitplus.wallet.lib.etsi.isTrustedBy
import at.asitplus.wallet.lib.etsi.isValidAt
import io.github.aakira.napier.Napier

/**
 * Validates [chain] against [trusted] anchors at [TimeScope.now], tolerating [TimeScope.timeLeeway]: every certificate
 * is valid and issued by the next one, and the last one is either one of [trusted] or issued by one of them.
 */
internal fun requireChainToAnchor(
    chain: CertificateChain,
    trusted: Collection<X509Certificate>,
    timeScope: TimeScope,
) {
    val now = timeScope.now
    val leeway = timeScope.timeLeeway
    Napier.d("Received chain with ${chain.size} certificate(s).")
    require(chain.isNotEmpty()) { "Certificate chain is empty." }

    chain.forEach { certificate ->
        require(certificate.isValidAt(now, leeway)) {
            if (certificate.isExpired(now, leeway)) "Certificate is expired: $certificate"
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

    require(trusted.isNotEmpty()) { "No trusted root certificates configured for request validation." }
    val top = chain.last()
    val topDer = top.encodeToDer()
    if (trusted.none { it.encodeToDer().contentEquals(topDer) }) {
        top.isTrustedBy(trusted.toList(), now, leeway).getOrThrow()
    }
    Napier.d("Chain validation completed (full chain validity enforced).")
}
