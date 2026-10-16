package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.requireTrustedSigningCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.requireChainToAnchor
import at.asitplus.wallet.lib.validation.CheckOutcome.*
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
     * itself an anchor: issuers of credentials, as `requireTrustedSigningCertificate` with `allowDirectTrust`.
     * A directly listed certificate may be self-signed, which OpenID4VC HAIP 1.0, 6.1.1 forbids for the issuer of an
     * SD-JWT VC.
     */
    ISSUED_BY_ANCHOR_OR_LISTED,

    /**
     * The signing certificate is issued by an anchor, the anchor is not transported, and the signer is not
     * self-signed, as OpenID4VC HAIP 1.0 requires for status list tokens (6.1), key attestations (4.5.1), wallet
     * attestations (4.4.1), and signed issuer metadata (4.1).
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
    }.fold(onSuccess = { Passed }, onFailure = { Failed(it) })
}

/**
 * Whether [chain] is authorized for [purpose] by the anchors of the signed [credentialIdentifier], see
 * [CredentialTrustAnchors]: issuers may be issued by an anchor or listed themselves, status list signers have to be
 * issued by an anchor (OpenID4VC HAIP 1.0, 6.1).
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
    val rule = when (purpose) {
        TrustPurpose.ISSUANCE -> TrustRule.ISSUED_BY_ANCHOR_OR_LISTED
        TrustPurpose.STATUS -> TrustRule.ISSUED_BY_ANCHOR
    }
    return TrustValidation(
        outcome = checkTrust(chain, anchors.certificates, at, rule),
        credentialIdentifier = credentialIdentifier,
        source = anchors.source
    )
}
