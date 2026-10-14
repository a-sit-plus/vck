package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.requireTrustedSigningCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.requireChainToAnchor
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import kotlin.time.Instant

/**
 * How the certificate chain transported with a signed artifact has to lead to a trust anchor.
 *
 * *None of the rules builds a path through intermediate certificates, evaluates `pathLenConstraint` or `keyUsage`,
 * or checks certificate revocation*
 */
internal enum class TrustRule {
    /**
     * The signing certificate is issued by an anchor, or the chain consists of only the signing certificate, which is
     * itself an anchor, as `requireTrustedSigningCertificate` with `allowDirectTrust`: issuers of credentials and
     * signers of status list tokens. A LoTE lists "certificates that can be used to verify the signature or seal
     * created by the provider" for its issuance and revocation services alike (ETSI TS 119 602 V1.1.1, 6.6.3, D.3,
     * G.3), which "can be the X.509 certificate corresponding to the private key used to sign or seal" (H.3, NOTE).
     * This relaxes OpenID4VC HAIP 1.0, which forbids a transported anchor and a self-signed signer for SD-JWT VCs
     * (6.1.1) and status list tokens (6.1): a directly listed certificate may be self-signed.
     */
    ISSUED_BY_ANCHOR_OR_LISTED,

    /**
     * The signing certificate is issued by an anchor, the anchor is not transported, and the signer is not
     * self-signed, as OpenID4VC HAIP 1.0 requires for key attestations (4.5.1) and wallet attestations (4.4.1).
     */
    ISSUED_BY_ANCHOR,

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
    return catching {
        when (rule) {
            TrustRule.ISSUED_BY_ANCHOR_OR_LISTED ->
                signer.requireTrustedSigningCertificate(TrustedCertificates { anchors }, at, allowDirectTrust = true)

            TrustRule.ISSUED_BY_ANCHOR ->
                signer.requireTrustedSigningCertificate(TrustedCertificates { anchors }, at, allowDirectTrust = false)

            TrustRule.CHAIN_TO_ANCHOR -> requireChainToAnchor(signer, anchors, at)
        }
    }.toOutcome()
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
    val anchors = catching { resolve(credentialIdentifier, purpose) }.getOrElse {
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
