package at.asitplus.wallet.lib.extensions

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.subjectKeyIdentifier
import at.asitplus.signum.indispensable.pki.X509Certificate

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
