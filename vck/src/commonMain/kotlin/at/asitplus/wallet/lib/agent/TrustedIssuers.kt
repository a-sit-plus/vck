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
fun interface TrustedIssuerCertificates {
    suspend operator fun invoke(): Set<X509Certificate>
}

/**
 * How to verify the issuer's signature on a JWS-based credential, i.e. an SD-JWT or a VC-JWS:
 * Against [trustedIssuers] if there are any, otherwise against the key asserted by the credential itself.
 *
 * Do not use this for holder signatures, i.e. key binding, proof of possession or a signed presentation,
 * those are self-asserted by design.
 */
fun issuerJwsVerifier(trustedIssuers: TrustedIssuerCertificates?): VerifyJwsObjectFun =
    trustedIssuers?.let { VerifyJwsObjectTrustedCertificate(trustedIssuers = it) } ?: VerifyJwsObject()

/**
 * How to verify the issuer's signature on a COSE-based credential, i.e. the `issuerAuth` of an mdoc:
 * Against [trustedIssuers] if there are any, otherwise against the certificate transported in the COSE headers.
 */
fun <P : Any> issuerCoseVerifier(trustedIssuers: TrustedIssuerCertificates?): VerifyCoseSignatureFun<P> =
    trustedIssuers?.let { VerifyCoseSignatureTrustedCertificate<P>(trustedIssuers = it) } ?: VerifyCoseSignature()

/**
 * Extracts the signing certificate, i.e. the [leaf], from this certificate chain, and requires it to be trusted:
 * It has to be signed by one of the certificates from [trustedIssuers], and both certificates have to be valid
 * at [at], see [isTrustedBy].
 *
 * The certificate of the trust anchor must be known out-of-band, so no certificate from [trustedIssuers] may
 * appear in this chain, and the signing certificate must not be self-signed. Unless [allowDirectTrust] is
 * disabled, one case is exempt from both rules: a chain consisting of exactly one self-signed certificate that
 * is itself contained in [trustedIssuers], i.e. an issuer whose own certificate we trust directly.
 *
 * @return the signing certificate, for use in signature verification
 */
// ponytail: single hop only, we don't build a certificate path, and we don't evaluate keyUsage or
// basicConstraints -- Signum 3.24.0 exposes no typed X.509 extensions, revisit once it does
internal suspend fun CertificateChain?.requireTrustedSigningCertificate(
    trustedIssuers: TrustedIssuerCertificates,
    at: Instant = Clock.System.now(),
    /** Whether a chain of exactly one self-signed certificate contained in [trustedIssuers] counts as trusted. */
    allowDirectTrust: Boolean = true,
): X509Certificate {
    val chain = this?.takeIf { it.isNotEmpty() }
        ?: throw IllegalArgumentException("No certificate transported with the signed object")
    val signingCertificate = chain.leaf
    val trusted = trustedIssuers()
    require(trusted.isNotEmpty()) { "No trusted issuer certificates" }
    require(signingCertificate.isValidAt(at)) { "Signing certificate is not valid at $at" }

    val isSelfSigned = signingCertificate.isIssuerOf(signingCertificate).isSuccess
    val isDirectlyTrusted = allowDirectTrust && chain.size == 1 && isSelfSigned && signingCertificate in trusted
    if (!isDirectlyTrusted) {
        require(chain.none { it in trusted }) {
            "The certificate of the trust anchor must not be transported with the signed object"
        }
        require(!isSelfSigned) { "The signing certificate must not be self-signed" }
        signingCertificate.isTrustedBy(trusted.toList(), at).getOrThrow()
    }
    return signingCertificate
}
