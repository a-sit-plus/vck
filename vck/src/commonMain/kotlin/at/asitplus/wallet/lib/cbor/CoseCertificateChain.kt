package at.asitplus.wallet.lib.cbor

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.extensions.authorityKeyIdentifier

/**
 * The `x5chain` of this COSE structure (RFC 9360, 2), from its protected or its unprotected header, DER-encoded in
 * either. ISO/IEC DIS 18013-5:2026 puts the one of an `IssuerAuth` into the unprotected header, but "An mdoc reader
 * should support the presence of the x5chain element in the protected header" (12.3.4).
 *
 * Fails if both headers carry a chain and they differ, or a certificate can not be decoded.
 */
internal fun CoseSigned<*>.certificateChain(): CertificateChain? {
    val protectedChain = protectedHeader.certificateChain?.takeIf { it.isNotEmpty() }
    val unprotectedChain = unprotectedHeader?.certificateChain?.takeIf { it.isNotEmpty() }
    if (protectedChain != null && unprotectedChain != null) {
        require(protectedChain.size == unprotectedChain.size &&
                protectedChain.zip(unprotectedChain).all { (a, b) -> a.contentEquals(b) }) {
            "The protected and unprotected header carry different certificate chains"
        }
    }
    return (protectedChain ?: unprotectedChain)?.map { X509Certificate.decodeFromDer(it) }
}

/**
 * The key identifiers of the authority key identifiers of the certificates in the [certificateChain] of this COSE
 * structure, e.g. of the `IssuerAuth` of an mdoc, which DCQL `trusted_authorities` of type `aki` (OpenID4VP 1.0,
 * 6.1.1) and ISO `issuerIdentifiers` (ISO/IEC DIS 18013-5:2026, 10.2.4) match. Empty without a chain, or if it can not
 * be read, so that nothing matches.
 */
internal fun CoseSigned<*>.authorityKeyIdentifiers(): List<ByteArray> =
    catchingUnwrapped { certificateChain() }.getOrNull().orEmpty().mapNotNull { it.authorityKeyIdentifier }
