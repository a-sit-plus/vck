package at.asitplus.wallet.lib.validation

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.agent.validation.relyingParty.requireChainToAnchor
import at.asitplus.wallet.lib.etsi.isIssuerOf
import at.asitplus.wallet.lib.etsi.isValidAt
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import kotlin.time.Instant

/**
 * How the certificate chain transported with a signed artifact has to lead to a trust anchor.
 *
 * *None of the rules builds a path other than the transported one, evaluates `pathLenConstraint` or `keyUsage`, or
 * checks certificate revocation*
 */
internal enum class TrustRule {
    /**
     * The signing certificate is itself an anchor, regardless of the certificates transported with it, or the chain is
     * a path from the signing certificate through intermediate certificates to one issued by an anchor, see
     * [requireListedOrIssuedByAnchor]: issuers of credentials, signers of status list tokens, and wallet providers.
     *
     * A LoTE lists "certificates that can be used to verify the signature or seal created by the provider" for its
     * issuance and revocation services alike (ETSI TS 119 602 V1.1.1, 6.6.3, D.3, E.3, G.3), which "can be the X.509
     * certificate corresponding to the private key used to sign or seal" (H.3, NOTE), and an attestation of a wallet
     * provider "verifies under the Wallet Provider's public key as found on the Trusted List of Wallet Providers" (ETSI
     * TS 119 472-3 V1.1.1, AUTH-REQ-PROC-4.4.3-01, TOKEN-REQ-PROC-4.5.2-01, CRED-REQ-PROC-4.6.2.1-01,
     * CRED-REQ-PROC-4.6.2.2-01). Wallet providers sign it so that the signature "can be validated by means of a
     * certificate listed" on that list (CIR (EU) 2024/2979, Article 6(1), as amended by CIR (EU) 2026/1731), and its
     * signing certificate "can be verified with a trust anchor on the list of wallet providers [...], potentially using
     * intermediate certificates included in the x5c parameter" (Annex Ib, TR-WIA-4.1, TR_KA-5): the path ends at the
     * listed certificate, so certificates transported beyond it, e.g. the issuer of a listed signer, are ignored, as in
     * RFC 5280, 6.1. This relaxes OpenID4VC HAIP 1.0, which forbids a transported anchor and a
     * self-signed signer for SD-JWT VCs (6.1.1), status list tokens (6.1), and key attestations (4.5.1): a directly
     * listed certificate may be self-signed. Intermediate certificates may be transported with the signing
     * certificate, "except the trust anchor" (ETSI TS 119 472-1 V1.2.1, EAA-4.6.1-06; EUDI TS3, 2.2.1.2, 2.2.2.2), but
     * an anchor transported nonetheless at the end of the chain is tolerated, as signers in the wild do so.
     */
    ISSUED_BY_ANCHOR_OR_LISTED,

    /**
     * Every certificate of the chain is valid and issued by the next one, and the last one is an anchor or issued by
     * one: wallet-relying party access and registration certificates, as `WrpChainValidator`.
     */
    CHAIN_TO_ANCHOR,
}

/**
 * Whether [chain] leads to one of [anchors] at [at], following [rule]. Only evaluates: whether the outcome rejects is
 * up to the [TrustPolicy].
 *
 * Blocked if no anchors are configured at all (`null`), failed if there are none, as the configured trust source
 * then authorizes no signer, and failed if the chain does not lead to an anchor.
 */
// TODO Evaluate the revocation of every certificate in the path, as path validation requires ("the certificate is not
//  revoked", RFC 5280, 6.1.3 (a)(3)), once CRL and OCSP are supported
internal suspend fun checkTrust(
    chain: CertificateChain?,
    anchors: Set<X509Certificate>?,
    at: Instant,
    rule: TrustRule,
): CheckOutcome {
    if (anchors == null) return Blocked(IllegalStateException("No trust anchors configured"))
    if (anchors.isEmpty()) return Failed(IllegalArgumentException("No trust anchor authorizes the signer"))
    val signer = chain?.takeIf { it.isNotEmpty() }
        ?: return Failed(IllegalArgumentException("No certificate transported with the signed object"))
    return catchingUnwrapped {
        when (rule) {
            TrustRule.ISSUED_BY_ANCHOR_OR_LISTED -> requireListedOrIssuedByAnchor(signer, anchors, at)
            TrustRule.CHAIN_TO_ANCHOR -> requireChainToAnchor(signer, anchors, at)
        }
    }.toOutcome()
}

/**
 * Requires the signing certificate of [chain] to be one of [anchors], valid at [at], or [chain] to lead to one of them,
 * see [requireChainToAnchor]: every certificate certifies the previous one (RFC 7515, 4.1.6) and is valid at [at], and
 * the last one is issued by one of [anchors]. Then the signing certificate must not be self-signed (OpenID4VC HAIP 1.0,
 * 4.5.1, 6.1, 6.1.1), and no anchor may be transported, as its certificate must be known out-of-band, except as the
 * last certificate of [chain], which is then ignored.
 */
private fun requireListedOrIssuedByAnchor(chain: CertificateChain, anchors: Set<X509Certificate>, at: Instant) {
    // Compare the full certificate, not just its key: a listed signer does not confer trust on other certificates
    // sharing that key
    fun isListed(certificate: X509Certificate) = anchors.any {
        it.encodeToDer().contentEquals(certificate.encodeToDer())
    }

    // A listed signer is trusted itself, so the certificates transported with it, e.g. its issuer, confer nothing
    val signer = chain.leaf
    if (isListed(signer)) {
        require(signer.isValidAt(at)) { "Signing certificate is not valid at $at" }
        return
    }
    // A transported anchor confers no trust, as it is compared to the configured ones anyway, so tolerate it at the
    // end of the chain, where signers transporting it put it
    val path = if (isListed(chain.last())) chain.dropLast(1) else chain
    require(path.none(::isListed)) {
        "The certificate of the trust anchor must only be transported as the last one of the chain"
    }
    require(signer.isIssuerOf(signer).isFailure) { "The signing certificate must not be self-signed" }
    requireChainToAnchor(path, anchors, at)
}

/**
 * Whether [chain] is authorized for [purpose] by the anchors of the signed [credentialIdentifier], see
 * [CredentialTrustAnchors]: issuers and status list signers alike may be issued by an anchor or listed themselves,
 * see [TrustRule.ISSUED_BY_ANCHOR_OR_LISTED].
 *
 * Blocked if no [CredentialTrustAnchors] are configured, no scope covers the type, or its anchors are unavailable.
 */
internal suspend fun CredentialTrustAnchors?.checkCredentialTrust(
    credentialIdentifier: String,
    purpose: TrustPurpose,
    chain: CertificateChain?,
    at: Instant,
): TrustValidation {
    if (this == null) {
        return TrustValidation(
            outcome = Blocked(IllegalStateException("No credential trust anchors configured")),
            credentialIdentifier = credentialIdentifier,
        )
    }
    val anchors = catchingUnwrapped { resolve(credentialIdentifier, purpose) }.getOrElse {
        return TrustValidation(
            outcome = Blocked(it),
            credentialIdentifier = credentialIdentifier
        )
    } ?: return TrustValidation(
        outcome = Blocked(IllegalArgumentException("No trust scope covers $credentialIdentifier")),
        credentialIdentifier = credentialIdentifier,

        )
    return TrustValidation(
        outcome = checkTrust(chain, anchors.certificates, at, TrustRule.ISSUED_BY_ANCHOR_OR_LISTED),
        credentialIdentifier = credentialIdentifier,
        source = anchors.source
    )
}
