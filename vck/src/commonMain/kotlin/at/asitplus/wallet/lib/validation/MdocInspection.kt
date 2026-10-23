package at.asitplus.wallet.lib.validation

import at.asitplus.catchingUnwrapped
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import at.asitplus.wallet.mdl.MDL_DOCTYPE
import at.asitplus.wallet.mdl.MDL_NAMESPACE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements

/*
 * Checks of the inspection procedure for issuer data authentication of an mdoc that relate the MSO to the document
 * signer certificate it is signed with (ISO/IEC 18013-5:2021, 9.3.1; ISO/IEC DIS 18013-5 second edition, 12.8.1).
 */

/**
 * Whether the `validityInfo` of this MSO is consistent (ISO/IEC 18013-5:2021, 9.1.2.4; second edition, 12.3.4):
 * `validFrom` is equal to or later than `signed`, and `validUntil` is later than `validFrom`.
 */
internal fun MobileSecurityObject.validityIsConsistent(): CheckOutcome = with(validityInfo) {
    when {
        validFrom < signed -> Failed(IllegalArgumentException("The MSO is valid from before it was signed"))
        validUntil <= validFrom -> Failed(IllegalArgumentException("The MSO is valid until before it is valid from"))
        else -> Passed
    }
}

/**
 * Whether this MSO was signed within the validity period of the certificate [signer] signed it with
 * (ISO/IEC 18013-5:2021, 9.3.1 step 5; second edition, 12.8.1 step 5). [timeScope] applies its leeway, as to every time
 * comparison of a validation, e.g. for an issuer that sets `signed` slightly before the time of signing.
 */
internal fun MobileSecurityObject.isSignedWithinValidityOf(signer: X509Certificate, timeScope: TimeScope): CheckOutcome {
    val signed = validityInfo.signed
    val notBefore = signer.tbsCertificate.validFrom.instant
    val notAfter = signer.tbsCertificate.validUntil.instant
    return when {
        signed < notBefore - timeScope.timeLeeway ->
            Failed(IllegalArgumentException("The MSO was signed before its document signer certificate is valid"))

        signed > notAfter + timeScope.timeLeeway ->
            Failed(IllegalArgumentException("The MSO was signed after its document signer certificate expired"))

        else -> Passed
    }
}

/**
 * Whether this MSO expires no later than the certificate [signer] signed it with, as issuers have to ensure
 * (ISO/IEC 18013-5:2021, 9.1.2.4). A reader may reject an MSO valid until after its document signer certificate
 * expires (9.3.1 step 5; second edition, 12.8.1 step 5), so this is reported, but not required.
 */
internal fun MobileSecurityObject.expiresWithin(signer: X509Certificate): CheckOutcome =
    if (validityInfo.validUntil <= signer.tbsCertificate.validUntil.instant) Passed
    else Failed(IllegalArgumentException("The MSO is valid until after its document signer certificate expires"))

/**
 * Whether the issuing authority of an mDL, as far as its elements are disclosed, agrees with the certificate [signer]
 * that signed its MSO (ISO/IEC 18013-5:2021, 7.2.1; second edition, 13.4.2): `issuing_country` equals the
 * `countryName` of the subject of [signer], and `issuing_jurisdiction` its `stateOrProvinceName`, which is only
 * required if [signer] has one. Passes for other document types, and for elements that are not disclosed.
 *
 * A document signer certificate without `countryName` violates its profile (Annex B.1.4), which is not validated, as
 * none of the certificate profiles are, so `issuing_country` is not compared with it either.
 */
internal fun IssuerSigned.issuingAuthorityAgreesWith(docType: String, signer: X509Certificate): CheckOutcome {
    if (docType != MDL_DOCTYPE) return Passed
    val disclosed = namespaces?.get(MDL_NAMESPACE)?.entries.orEmpty()
        .associate { it.value.elementIdentifier to it.value.elementValue }
    val country = signer.subjectCountryName
    disclosed[MobileDrivingLicenceDataElements.ISSUING_COUNTRY]?.let { issuingCountry ->
        if (country != null && issuingCountry != country) return Failed(
            IllegalArgumentException("The issuing_country does not match the country of the document signer")
        )
    }
    val state = signer.subjectStateOrProvinceName ?: return Passed
    disclosed[MobileDrivingLicenceDataElements.ISSUING_JURISDICTION]?.let { jurisdiction ->
        if (jurisdiction != state) return Failed(
            IllegalArgumentException("The issuing_jurisdiction does not match the state or province of the document signer")
        )
    }
    return Passed
}

/**
 * Whether [target], a certificate issued under the IACA certificate [iaca], is of the same country, and of the same
 * state or province if both have one (ISO/IEC 18013-5:2021, 9.3.3; second edition, 12.8.3): their subjects have the
 * same `countryName`, and the same `stateOrProvinceName` if both have that element.
 */
internal fun requireSameIssuingAuthority(iaca: X509Certificate, target: X509Certificate) {
    require(iaca.subjectCountryName == target.subjectCountryName) {
        "The countryName of the signer certificate differs from the one of the IACA certificate"
    }
    val iacaState = iaca.subjectStateOrProvinceName
    val targetState = target.subjectStateOrProvinceName
    require(iacaState == null || targetState == null || iacaState == targetState) {
        "The stateOrProvinceName of the signer certificate differs from the one of the IACA certificate"
    }
}

/** `stateOrProvinceName` (X.520, 6.3.2) */
private val stateOrProvinceName = ObjectIdentifier("2.5.4.8")

private val X509Certificate.subjectAttributes
    get() = tbsCertificate.subjectName.flatMap { it.attrsAndValues }

/** The `countryName` of the subject of this certificate, if it has one. */
internal val X509Certificate.subjectCountryName: String?
    get() = subjectAttributes.firstOrNull { it is AttributeTypeAndValue.Country }?.stringValue()

/** The `stateOrProvinceName` of the subject of this certificate, if it has one. */
internal val X509Certificate.subjectStateOrProvinceName: String?
    get() = subjectAttributes.firstOrNull { it.oid == stateOrProvinceName }?.stringValue()

private fun AttributeTypeAndValue.stringValue(): String? = (value as? Asn1Primitive)
    ?.let { catchingUnwrapped { Asn1String.decodeFromTlv(it).value }.getOrNull() }
