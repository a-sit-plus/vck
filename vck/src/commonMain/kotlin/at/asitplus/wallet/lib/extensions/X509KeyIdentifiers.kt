package at.asitplus.wallet.lib.extensions

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.subjectKeyIdentifier
import at.asitplus.signum.indispensable.asn1.authorityKeyIdentifier_2_5_29_35
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.procedures.dcql.AuthorityKeyIdentifier

/**
 * The key identifier of the subject key identifier extension of this certificate, or `null` if it has none or it can
 * not be parsed (RFC 5280, 4.2.1.2: `SubjectKeyIdentifier ::= KeyIdentifier`, `KeyIdentifier ::= OCTET STRING`).
 *
 * Certificates this certificate issues carry it as their authority key identifier: "the value of the subject key
 * identifier MUST be the value placed in the key identifier field of the authority key identifier extension
 * (Section 4.2.1.1) of certificates issued by the subject of this certificate" (ibid.).
 */
val X509Certificate.subjectKeyIdentifier: ByteArray?
    get() = tbsCertificate.extensions
        ?.firstOrNull { it.oid == KnownOIDs.subjectKeyIdentifier }
        ?.let { extension ->
            catchingUnwrapped {
                Asn1Element.parse(extension.value.asOctetString().content).asOctetString().content
            }.getOrNull()
        }

/**
 * The key identifier of the authority key identifier extension of this certificate, or `null` if it has none, it has
 * only the issuer and serial number of the issuing certificate, or it can not be parsed (RFC 5280, 4.2.1.1:
 * `keyIdentifier [0] KeyIdentifier OPTIONAL`). It is the [subjectKeyIdentifier] of the certificate that issued this
 * one.
 */
internal val X509Certificate.authorityKeyIdentifier: ByteArray?
    get() = tbsCertificate.extensions
        ?.firstOrNull { it.oid == KnownOIDs.authorityKeyIdentifier_2_5_29_35 }
        ?.let { extension ->
            AuthorityKeyIdentifier.decodeFromDerSafe(extension.value.asEncapsulatingOctetString().content)
                .getOrNull()?.keyIdentifier
        }
