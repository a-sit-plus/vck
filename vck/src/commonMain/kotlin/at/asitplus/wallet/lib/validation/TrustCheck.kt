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
     * [HAIP-X5C] forbids a self-signed signer of an SD-JWT VC, which a directly listed one may be (L1).
     */
    ISSUED_BY_ANCHOR_OR_LISTED,

    /**
     * The signing certificate is issued by an anchor, the anchor is not transported, and the signer is not
     * self-signed: status list tokens [HAIP-STATUS], key attestations [HAIP-KA], wallet attestations [HAIP-WIA],
     * and signed metadata [HAIP-METADATA].
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
// TODO Evaluate the revocation of every certificate in the path, RFC 5280 6.1.3 (a)(3) [RFC5280-PATH], once CRL
//  and OCSP are supported (L1)
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
 * issued by an anchor [HAIP-STATUS].
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

/*
 * References
 *
 * | Tag           | Source                                                                                      |
 * |---------------|---------------------------------------------------------------------------------------------|
 * | HAIP-METADATA | OpenID4VC HAIP 1.0 (2025-12-24), 4.1 Issuer Metadata: x5c, trust anchor not included,       |
 * |               | signer not self-signed                                                                      |
 * | HAIP-WIA      | OpenID4VC HAIP 1.0, 4.4.1 Wallet Attestation: certificate and chain excluding the trust     |
 * |               | anchor in x5c                                                                               |
 * | HAIP-KA       | OpenID4VC HAIP 1.0, 4.5.1 Key Attestation: trust anchor not included, signer not            |
 * |               | self-signed                                                                                 |
 * | HAIP-STATUS   | OpenID4VC HAIP 1.0, 6.1 IETF SD-JWT VC Profile: Status List Token key in x5c, trust anchor  |
 * |               | not included, signer not self-signed                                                        |
 * | HAIP-X5C      | OpenID4VC HAIP 1.0, 6.1.1 Issuer identification and key resolution: issuer certificate and  |
 * |               | chain in x5c, trust anchor not included, signer not self-signed                             |
 * | RFC5280-PATH  | RFC 5280, 6.1.3 (a)(3): "the certificate is not revoked"                                    |
 */
