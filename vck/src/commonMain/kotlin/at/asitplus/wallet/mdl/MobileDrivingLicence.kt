package at.asitplus.wallet.mdl

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.LocalDate
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString


/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mDL (7.2.1)
 */
@Serializable
data class MobileDrivingLicence(
    /** Last name, surname, or primary identifier of the mDL holder. */
    @SerialName(MobileDrivingLicenceDataElements.FAMILY_NAME)
    val familyName: String,

    /** First name(s), other name(s), or secondary identifier, of the mDL holder. */
    @SerialName(MobileDrivingLicenceDataElements.GIVEN_NAME)
    val givenName: String,

    /** Day, month and year on which the mDL holder was born. If unknown, approximate date of birth. */
    @SerialName(MobileDrivingLicenceDataElements.BIRTH_DATE)
    val dateOfBirth: LocalDate? = null,

    /** Date when mDL was issued. */
    @SerialName(MobileDrivingLicenceDataElements.ISSUE_DATE)
    val issueDate: LocalDate,

    /** Date when mDL expires. */
    @SerialName(MobileDrivingLicenceDataElements.EXPIRY_DATE)
    val expiryDate: LocalDate,

    /** Alpha-2 country code, as defined in ISO 3166-1, of the issuing authority's country or territory. */
    @SerialName(MobileDrivingLicenceDataElements.ISSUING_COUNTRY)
    val issuingCountry: String? = null,

    /** Issuing authority name. */
    @SerialName(MobileDrivingLicenceDataElements.ISSUING_AUTHORITY)
    val issuingAuthority: String? = null,

    /** The number assigned or calculated by the issuing authority. */
    @SerialName(MobileDrivingLicenceDataElements.DOCUMENT_NUMBER)
    val licenceNumber: String,

    /** A reproduction of the mDL holder's portrait. */
    @SerialName(MobileDrivingLicenceDataElements.PORTRAIT)
    @ByteString
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val portrait: ByteArray,

    /** Driving privileges of the mDL holder. */
    @SerialName(MobileDrivingLicenceDataElements.DRIVING_PRIVILEGES)
    val drivingPrivileges: Array<DrivingPrivilege>,

    /** Distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F.  */
    @SerialName(MobileDrivingLicenceDataElements.UN_DISTINGUISHING_SIGN)
    val unDistinguishingSign: String? = null,

    /** An audit control number assigned by the issuing authority. */
    @SerialName(MobileDrivingLicenceDataElements.ADMINISTRATIVE_NUMBER)
    val administrativeNumber: String? = null,

    /** mDL holder's sex using values as defined in ISO/IEC 5218. */
    @SerialName(MobileDrivingLicenceDataElements.SEX)
    @Serializable(with = IsoSexEnumSerializer::class)
    val sex: IsoSexEnum? = null,

    /** mDL holder's height in centimetres. */
    @SerialName(MobileDrivingLicenceDataElements.HEIGHT)
    val height: UInt? = null,

    /** mDL holder's weight in kilograms */
    @SerialName(MobileDrivingLicenceDataElements.WEIGHT)
    val weight: UInt? = null,

    /** mDL holder's eye colour. The value shall be one of the following: "black", "blue", "brown",
     * "dichromatic", "grey", "green", "hazel", "maroon", "pink", "unknown". */
    @SerialName(MobileDrivingLicenceDataElements.EYE_COLOUR)
    val eyeColor: String? = null,

    /** mDL holder's hair color. The value shall be one of the following: "bald", "black", "blond",
     *  "brown", "grey", "red", "auburn", "sandy","white", "unknown"  */
    @SerialName(MobileDrivingLicenceDataElements.HAIR_COLOUR)
    val hairColor: String? = null,

    /** Country and municipality or state/province where the mDL holder was born. */
    @SerialName(MobileDrivingLicenceDataElements.BIRTH_PLACE)
    val placeOfBirth: String? = null,

    /** The place where the mDL holder resides and/or may be contracted. */
    @SerialName(MobileDrivingLicenceDataElements.RESIDENT_ADDRESS)
    val placeOfResidence: String? = null,

    /** Date when portrait was taken. */
    @SerialName(MobileDrivingLicenceDataElements.PORTRAIT_CAPTURE_DATE)
    val portraitImageTimestamp: LocalDate? = null,

    /** The age of the mDL holder. */
    @SerialName(MobileDrivingLicenceDataElements.AGE_IN_YEARS)
    val ageInYears: UInt? = null,

    /** The year when the mDL holder was born. */
    @SerialName(MobileDrivingLicenceDataElements.AGE_BIRTH_YEAR)
    val ageBirthYear: UInt? = null,

    /** Age attestation: Over 12 years old? */
    @SerialName(MobileDrivingLicenceDataElements.AGE_OVER_12)
    val ageOver12: Boolean? = null,

    /** Age attestation: Over 13 years old? */
    @SerialName(MobileDrivingLicenceDataElements.AGE_OVER_13)
    val ageOver13: Boolean? = null,

    /** Age attestation: Over 14 years old? */
    @SerialName(MobileDrivingLicenceDataElements.AGE_OVER_14)
    val ageOver14: Boolean? = null,

    /** Age attestation: Over 16 years old? */
    @SerialName(MobileDrivingLicenceDataElements.AGE_OVER_16)
    val ageOver16: Boolean? = null,

    /** Age attestation: Over 18 years old? */
    @SerialName(MobileDrivingLicenceDataElements.AGE_OVER_18)
    val ageOver18: Boolean? = null,

    /** Age attestation: Over 21 years old? */
    @SerialName(MobileDrivingLicenceDataElements.AGE_OVER_21)
    val ageOver21: Boolean? = null,

    /** Age attestation: Over 25 years old? */
    @SerialName(MobileDrivingLicenceDataElements.AGE_OVER_25)
    val ageOver25: Boolean? = null,

    /** Age attestation: Over 60 years old? */
    @SerialName(MobileDrivingLicenceDataElements.AGE_OVER_60)
    val ageOver60: Boolean? = null,

    /** Age attestation: Over 62 years old? */
    @SerialName(MobileDrivingLicenceDataElements.AGE_OVER_62)
    val ageOver62: Boolean? = null,

    /** Age attestation: Over 65 years old? */
    @SerialName(MobileDrivingLicenceDataElements.AGE_OVER_65)
    val ageOver65: Boolean? = null,

    /** Age attestation: Over 68 years old? */
    @SerialName(MobileDrivingLicenceDataElements.AGE_OVER_68)
    val ageOver68: Boolean? = null,

    /** Country subdivision code of the jurisdiction that issued the mDL as defined in ISO 3166-2:2020, Clause 8. */
    @SerialName(MobileDrivingLicenceDataElements.ISSUING_JURISDICTION)
    val issuingJurisdiction: String? = null,

    /** Nationality of the mDL holder as a two letter country code (alpha-2 code) defined in ISO 3166-1. */
    @SerialName(MobileDrivingLicenceDataElements.NATIONALITY)
    val nationality: String? = null,

    /** The city where the mDL holder lives. */
    @SerialName(MobileDrivingLicenceDataElements.RESIDENT_CITY)
    val residentCity: String? = null,

    /** The state/province/district where the mDL holder lives. */
    @SerialName(MobileDrivingLicenceDataElements.RESIDENT_STATE)
    val residentState: String? = null,

    /** The postal code of the mDL holder. */
    @SerialName(MobileDrivingLicenceDataElements.RESIDENT_POSTAL_CODE)
    val residentPostalCode: String? = null,

    /** The country where the mDL holder lives as a two letter country code (alpha-2 code) defined in ISO 3166-1. */
    @SerialName(MobileDrivingLicenceDataElements.RESIDENT_COUNTRY)
    val residentCountry: String? = null,

    /** The family name of the mDL holder using full UTF-8 character set. */
    @SerialName(MobileDrivingLicenceDataElements.FAMILY_NAME_NATIONAL_CHARACTER)
    val familyNameNationalCharacters: String? = null,

    /** The given name of the mDL holder using full UTF-8 character set. */
    @SerialName(MobileDrivingLicenceDataElements.GIVEN_NAME_NATIONAL_CHARACTER)
    val givenNameNationalCharacters: String? = null,

    /** Image of the signature or usual mark of the mDL holder. */
    @ByteString
    @SerialName(MobileDrivingLicenceDataElements.SIGNATURE_USUAL_MARK)
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val signatureOrUsualMark: ByteArray? = null,

    /** This element contains optional facial information of the mDL holder. */
    @ByteString
    @SerialName(MobileDrivingLicenceDataElements.BIOMETRIC_TEMPLATE_FACE)
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val biometricTemplateFace: ByteArray? = null,

    /** This element contains optional fingerprint information of the mDL holder. */
    @ByteString
    @SerialName(MobileDrivingLicenceDataElements.BIOMETRIC_TEMPLATE_FINGER)
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val biometricTemplateFinger: ByteArray? = null,

    /** This element contains optional signature/sign information of the mDL holder. */
    @ByteString
    @SerialName(MobileDrivingLicenceDataElements.BIOMETRIC_TEMPLATE_SIGNATURE_SIGN)
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val biometricTemplateSignatureSign: ByteArray? = null,

    /** This element contains optional iris information of the mDL holder. */
    @ByteString
    @SerialName(MobileDrivingLicenceDataElements.BIOMETRIC_TEMPLATE_IRIS)
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val biometricTemplateIris: ByteArray? = null,
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as MobileDrivingLicence

        if (ageOver12 != other.ageOver12) return false
        if (ageOver13 != other.ageOver13) return false
        if (ageOver14 != other.ageOver14) return false
        if (ageOver16 != other.ageOver16) return false
        if (ageOver18 != other.ageOver18) return false
        if (ageOver21 != other.ageOver21) return false
        if (ageOver25 != other.ageOver25) return false
        if (ageOver60 != other.ageOver60) return false
        if (ageOver62 != other.ageOver62) return false
        if (ageOver65 != other.ageOver65) return false
        if (ageOver68 != other.ageOver68) return false
        if (familyName != other.familyName) return false
        if (givenName != other.givenName) return false
        if (dateOfBirth != other.dateOfBirth) return false
        if (issueDate != other.issueDate) return false
        if (expiryDate != other.expiryDate) return false
        if (issuingCountry != other.issuingCountry) return false
        if (issuingAuthority != other.issuingAuthority) return false
        if (licenceNumber != other.licenceNumber) return false
        if (!portrait.contentEquals(other.portrait)) return false
        if (!drivingPrivileges.contentEquals(other.drivingPrivileges)) return false
        if (unDistinguishingSign != other.unDistinguishingSign) return false
        if (administrativeNumber != other.administrativeNumber) return false
        if (sex != other.sex) return false
        if (height != other.height) return false
        if (weight != other.weight) return false
        if (eyeColor != other.eyeColor) return false
        if (hairColor != other.hairColor) return false
        if (placeOfBirth != other.placeOfBirth) return false
        if (placeOfResidence != other.placeOfResidence) return false
        if (portraitImageTimestamp != other.portraitImageTimestamp) return false
        if (ageInYears != other.ageInYears) return false
        if (ageBirthYear != other.ageBirthYear) return false
        if (issuingJurisdiction != other.issuingJurisdiction) return false
        if (nationality != other.nationality) return false
        if (residentCity != other.residentCity) return false
        if (residentState != other.residentState) return false
        if (residentPostalCode != other.residentPostalCode) return false
        if (residentCountry != other.residentCountry) return false
        if (familyNameNationalCharacters != other.familyNameNationalCharacters) return false
        if (givenNameNationalCharacters != other.givenNameNationalCharacters) return false
        if (!signatureOrUsualMark.contentEquals(other.signatureOrUsualMark)) return false
        if (!biometricTemplateFace.contentEquals(other.biometricTemplateFace)) return false
        if (!biometricTemplateFinger.contentEquals(other.biometricTemplateFinger)) return false
        if (!biometricTemplateSignatureSign.contentEquals(other.biometricTemplateSignatureSign)) return false
        if (!biometricTemplateIris.contentEquals(other.biometricTemplateIris)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ageOver12?.hashCode() ?: 0
        result = 31 * result + (ageOver13?.hashCode() ?: 0)
        result = 31 * result + (ageOver14?.hashCode() ?: 0)
        result = 31 * result + (ageOver16?.hashCode() ?: 0)
        result = 31 * result + (ageOver18?.hashCode() ?: 0)
        result = 31 * result + (ageOver21?.hashCode() ?: 0)
        result = 31 * result + (ageOver25?.hashCode() ?: 0)
        result = 31 * result + (ageOver60?.hashCode() ?: 0)
        result = 31 * result + (ageOver62?.hashCode() ?: 0)
        result = 31 * result + (ageOver65?.hashCode() ?: 0)
        result = 31 * result + (ageOver68?.hashCode() ?: 0)
        result = 31 * result + familyName.hashCode()
        result = 31 * result + givenName.hashCode()
        result = 31 * result + (dateOfBirth?.hashCode() ?: 0)
        result = 31 * result + issueDate.hashCode()
        result = 31 * result + expiryDate.hashCode()
        result = 31 * result + (issuingCountry?.hashCode() ?: 0)
        result = 31 * result + (issuingAuthority?.hashCode() ?: 0)
        result = 31 * result + licenceNumber.hashCode()
        result = 31 * result + portrait.contentHashCode()
        result = 31 * result + drivingPrivileges.contentHashCode()
        result = 31 * result + (unDistinguishingSign?.hashCode() ?: 0)
        result = 31 * result + (administrativeNumber?.hashCode() ?: 0)
        result = 31 * result + (sex?.hashCode() ?: 0)
        result = 31 * result + (height?.hashCode() ?: 0)
        result = 31 * result + (weight?.hashCode() ?: 0)
        result = 31 * result + (eyeColor?.hashCode() ?: 0)
        result = 31 * result + (hairColor?.hashCode() ?: 0)
        result = 31 * result + (placeOfBirth?.hashCode() ?: 0)
        result = 31 * result + (placeOfResidence?.hashCode() ?: 0)
        result = 31 * result + (portraitImageTimestamp?.hashCode() ?: 0)
        result = 31 * result + (ageInYears?.hashCode() ?: 0)
        result = 31 * result + (ageBirthYear?.hashCode() ?: 0)
        result = 31 * result + (issuingJurisdiction?.hashCode() ?: 0)
        result = 31 * result + (nationality?.hashCode() ?: 0)
        result = 31 * result + (residentCity?.hashCode() ?: 0)
        result = 31 * result + (residentState?.hashCode() ?: 0)
        result = 31 * result + (residentPostalCode?.hashCode() ?: 0)
        result = 31 * result + (residentCountry?.hashCode() ?: 0)
        result = 31 * result + (familyNameNationalCharacters?.hashCode() ?: 0)
        result = 31 * result + (givenNameNationalCharacters?.hashCode() ?: 0)
        result = 31 * result + (signatureOrUsualMark?.contentHashCode() ?: 0)
        result = 31 * result + (biometricTemplateFace?.contentHashCode() ?: 0)
        result = 31 * result + (biometricTemplateFinger?.contentHashCode() ?: 0)
        result = 31 * result + (biometricTemplateSignatureSign?.contentHashCode() ?: 0)
        result = 31 * result + (biometricTemplateIris?.contentHashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "MobileDrivingLicence(" +
                "familyName='$familyName', " +
                "givenName='$givenName', " +
                "dateOfBirth=$dateOfBirth, " +
                "issueDate=$issueDate, " +
                "expiryDate=$expiryDate, " +
                "issuingCountry=$issuingCountry, " +
                "issuingAuthority=$issuingAuthority, " +
                "licenceNumber='$licenceNumber', " +
                "portrait=${portrait.encodeToString(Base16(strict = true))}, " +
                "drivingPrivileges=${drivingPrivileges.contentToString()}, " +
                "unDistinguishingSign=$unDistinguishingSign, " +
                "administrativeNumber=$administrativeNumber, " +
                "sex=$sex, " +
                "height=$height, " +
                "weight=$weight, " +
                "eyeColor=$eyeColor, " +
                "hairColor=$hairColor, " +
                "placeOfBirth=$placeOfBirth, " +
                "placeOfResidence=$placeOfResidence, " +
                "portraitImageTimestamp=$portraitImageTimestamp, " +
                "ageInYears=$ageInYears, " +
                "ageBirthYear=$ageBirthYear, " +
                "ageOver12=$ageOver12, " +
                "ageOver13=$ageOver13, " +
                "ageOver14=$ageOver14, " +
                "ageOver16=$ageOver16, " +
                "ageOver18=$ageOver18, " +
                "ageOver21=$ageOver21, " +
                "ageOver25=$ageOver25, " +
                "ageOver60=$ageOver60, " +
                "ageOver62=$ageOver62, " +
                "ageOver65=$ageOver65, " +
                "ageOver68=$ageOver68, " +
                "issuingJurisdiction=$issuingJurisdiction, " +
                "nationality=$nationality, " +
                "residentCity=$residentCity, " +
                "residentState=$residentState, " +
                "residentPostalCode=$residentPostalCode, " +
                "residentCountry=$residentCountry, " +
                "familyNameNationalCharacters=$familyNameNationalCharacters, " +
                "givenNameNationalCharacters=$givenNameNationalCharacters, " +
                "signatureOrUsualMark=${signatureOrUsualMark?.encodeToString(Base16(strict = true))}, " +
                "biometricTemplateFace=${biometricTemplateFace?.encodeToString(Base16(strict = true))}, " +
                "biometricTemplateFinger=${biometricTemplateFinger?.encodeToString(Base16(strict = true))}, " +
                "biometricTemplateSignatureSign=${biometricTemplateSignatureSign?.encodeToString(Base16(strict = true))}, " +
                "biometricTemplateIris=${biometricTemplateIris?.encodeToString(Base16(strict = true))}" +
                ")"
    }
}
