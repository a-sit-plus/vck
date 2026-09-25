package at.asitplus.wallet.lib.etsi

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.basicConstraints_2_5_29_19
import at.asitplus.signum.indispensable.asn1.encoding.decodeToBoolean
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.pki.X509Certificate

/**
 * The `BasicConstraints` extension of a certificate, see
 * [RFC 5280, Section 4.2.1.9](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9):
 *
 * ```asn1
 * BasicConstraints ::= SEQUENCE {
 *      cA                      BOOLEAN DEFAULT FALSE,
 *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 * ```
 *
 * Signum models certificate extensions as opaque [X509CertificateExtension.value] octet strings and exposes no
 * typed accessor for this one, so it is decoded here. Keep this decoding, not the trust rules built on it, in
 * sync with Signum: once it ships a typed `BasicConstraints`, [X509Certificate.basicConstraints] can delegate to
 * it and the rest of this file stays as it is.
 */
data class BasicConstraints(
    /** `cA`: whether the certified public key may be used to verify certificate signatures. */
    val certificateAuthority: Boolean,
    /**
     * `pathLenConstraint`: how many non-self-issued intermediate certificates may follow this one. Only
     * meaningful when [certificateAuthority] is set. Not evaluated by [isTrustedBy], which validates a single
     * hop and therefore never traverses an intermediate.
     */
    val pathLengthConstraint: Int?,
)

/**
 * The decoded `BasicConstraints` extension of this certificate, or `null` when it carries none.
 *
 * An end entity certificate legitimately has no `BasicConstraints` extension at all, which is why this is
 * nullable rather than defaulting to a non-CA value: "absent" and "present, saying not a CA" are different
 * statements, even though [isCertificateAuthority] treats both as "may not issue certificates".
 *
 * @throws Asn1StructuralException if the extension is present but malformed. A certificate whose constraints
 * cannot be read is not silently treated as unconstrained.
 */
val X509Certificate.basicConstraints: BasicConstraints?
    get() {
        val matches = tbsCertificate.extensions.orEmpty()
            .filter { it.oid == KnownOIDs.basicConstraints_2_5_29_19 }
        if (matches.isEmpty()) return null
        if (matches.size > 1) {
            throw Asn1StructuralException("More than one BasicConstraints extension in certificate")
        }
        // Parsed certificates carry the extension value as an encapsulating octet string when its content could
        // be parsed as ASN.1, and as a primitive one otherwise; a hand-built certificate may use either.
        val value = matches.single().value.asOctetString()
        val element = when (value) {
            is Asn1EncapsulatingOctetString -> value.children.singleOrNull()
                ?: throw Asn1StructuralException("BasicConstraints does not hold exactly one element")

            else -> Asn1Element.parse(value.content)
        }
        val sequence = element as? Asn1Sequence
            ?: throw Asn1StructuralException("BasicConstraints is not a SEQUENCE but ${element.tag}")

        var certificateAuthority = false
        var pathLengthConstraint: Int? = null
        // Dispatching on the tag rather than on position also accepts the (non-DER) encoding that spells out
        // `cA DEFAULT FALSE`, which some issuers emit.
        sequence.children.forEach { child ->
            when (child.tag) {
                Asn1Element.Tag.BOOL -> certificateAuthority = child.asPrimitive().decodeToBoolean()
                Asn1Element.Tag.INT -> pathLengthConstraint = child.asPrimitive().decodeToInt()
                else -> throw Asn1StructuralException("Unexpected element ${child.tag} in BasicConstraints")
            }
        }
        pathLengthConstraint?.let {
            if (it < 0) throw Asn1StructuralException("Negative pathLenConstraint $it in BasicConstraints")
        }
        return BasicConstraints(certificateAuthority, pathLengthConstraint)
    }

/**
 * Whether this certificate may issue certificates, i.e. whether it asserts `BasicConstraints` with `cA` set,
 * see [RFC 5280, Section 4.2.1.9](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9): "If the basic
 * constraints extension is not present [...] or the value of cA is not set to TRUE, then the certified public
 * key MUST NOT be used to verify certificate signatures."
 */
val X509Certificate.isCertificateAuthority: Boolean
    get() = basicConstraints?.certificateAuthority == true
