package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureTrustedCertificate
import at.asitplus.wallet.lib.etsi.isIssuerOf
import at.asitplus.wallet.lib.etsi.isTrustedBy
import at.asitplus.wallet.lib.etsi.isValidAt
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyJwsObjectTrustedCertificate
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * A fixed list of certificates of trusted issuers, e.g. extracted from an ETSI trust list with
 * [at.asitplus.wallet.lib.etsi.LoTEFilterService].
 *
 * Used by [at.asitplus.wallet.lib.jws.VerifyJwsObjectTrustedCertificate] and
 * [at.asitplus.wallet.lib.cbor.VerifyCoseSignatureTrustedCertificate] to decide whether the certificate
 * transported with a credential or token belongs to an issuer we trust.
 */
fun interface TrustedCertificates {
    suspend operator fun invoke(): Set<X509Certificate>
}

/**
 * How to verify the issuer's signature on a JWS-based credential, i.e. an SD-JWT or a VC-JWS:
 * Against [trustedIssuers] if there are any, otherwise against the key asserted by the credential itself.
 *
 * Do not use this for holder signatures, i.e. key binding, proof of possession or a signed presentation,
 * those are self-asserted by design.
 */
@Deprecated("Configure at.asitplus.wallet.lib.validation.CredentialValidator with trust anchors per credential type, see CredentialTrustAnchors. To be removed in the next major release.")
fun issuerJwsVerifier(trustedIssuers: TrustedCertificates?): VerifyJwsObjectFun =
    trustedIssuers?.let { VerifyJwsObjectTrustedCertificate(trustedIssuers = it) } ?: VerifyJwsObject()

/**
 * How to verify the issuer's signature on a COSE-based credential, i.e. the `issuerAuth` of an mdoc:
 * Against [trustedIssuers] if there are any, otherwise against the certificate transported in the COSE headers.
 */
@Deprecated("Configure at.asitplus.wallet.lib.validation.CredentialValidator with trust anchors per credential type, see CredentialTrustAnchors. To be removed in the next major release.")
fun <P : Any> issuerCoseVerifier(trustedIssuers: TrustedCertificates?): VerifyCoseSignatureFun<P> =
    trustedIssuers?.let { VerifyCoseSignatureTrustedCertificate<P>(trustedIssuers = it) } ?: VerifyCoseSignature()

/**
 * Extracts the signing certificate, i.e. the [leaf], from this certificate chain, and requires it to be trusted:
 * either the signing certificate itself is listed in [trustedIssuers], or it was issued by a listed certificate.
 * The signing certificate, and its issuer when applicable, must be valid at [at], see [isTrustedBy].
 *
 * The certificate of the trust anchor must be known out-of-band, so no certificate from [trustedIssuers] may
 * appear in this chain, except as its last certificate, which is then ignored, and the signing certificate must not
 * be self-signed. The anchor must also assert
 * `BasicConstraints` with `cA` set, see [isTrustedBy] and
 * [at.asitplus.wallet.lib.etsi.isCertificateAuthority].
 *
 * Unless [allowDirectTrust] is disabled, one case is exempt from all of those rules: a signing certificate that is
 * itself contained in [trustedIssuers], regardless of whether it is self-signed or CA-issued, and of the certificates
 * transported with it. This directly listed certificate verifies the signed object, not another certificate, so it
 * need not be a CA.
 *
 * @return the signing certificate, for use in signature verification
 */
// ponytail: single hop only, so we don't build a certificate path and never evaluate pathLenConstraint, and we
// don't evaluate keyUsage -- Signum exposes no typed X.509 extensions, BasicConstraints is decoded in
// at.asitplus.wallet.lib.etsi.basicConstraints, revisit once Signum ships its own
suspend fun CertificateChain?.requireTrustedSigningCertificate(
    trustedIssuers: TrustedCertificates,
    at: Instant = Clock.System.now(),
    /** Whether a signing certificate contained in [trustedIssuers] counts as directly trusted. */
    allowDirectTrust: Boolean = true,
): X509Certificate {
    val transported = this?.takeIf { it.isNotEmpty() }
        ?: throw IllegalArgumentException("No certificate transported with the signed object")
    val signingCertificate = transported.leaf
    val trusted = trustedIssuers()
    require(trusted.isNotEmpty()) { "No trusted issuer certificates" }
    require(signingCertificate.isValidAt(at)) { "Signing certificate is not valid at $at" }

    // Compare the full certificate, not just its key: a listed signer does not confer trust on other
    // certificates sharing that key. DER comparison also works when the transported certificate was decoded anew.
    fun isListed(certificate: X509Certificate) = trusted.any {
        it.encodeToDer().contentEquals(certificate.encodeToDer())
    }
    // A transported anchor confers no trust, as it is compared to the listed ones anyway, so tolerate it at the end
    // of the chain, where signers transporting it put it
    val chain = if (transported.size > 1 && isListed(transported.last())) transported.dropLast(1) else transported
    // A listed signer is trusted itself, so the certificates transported with it, e.g. its issuer, confer nothing
    val isDirectlyTrusted = allowDirectTrust && isListed(signingCertificate)
    if (!isDirectlyTrusted) {
        require(chain.none(::isListed)) {
            "The certificate of the trust anchor must only be transported as the last one of the chain"
        }
        val isSelfSigned = signingCertificate.isIssuerOf(signingCertificate).isSuccess
        require(!isSelfSigned) { "The signing certificate must not be self-signed" }
        signingCertificate.isTrustedBy(trusted.toList(), at).getOrThrow()
    }
    return signingCertificate
}
