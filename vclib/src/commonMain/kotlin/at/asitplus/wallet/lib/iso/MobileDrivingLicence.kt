@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.ADMINISTRATIVE_NUMBER
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.AGE_BIRTH_YEAR
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.AGE_IN_YEARS
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.AGE_OVER_18
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.BIRTH_DATE
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.BIRTH_PLACE
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.DOCUMENT_NUMBER
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.DRIVING_PRIVILEGES
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.EXPIRY_DATE
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.EYE_COLOUR
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.FAMILY_NAME
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.FAMILY_NAME_NATIONAL_CHARACTER
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.GIVEN_NAME
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.GIVEN_NAME_NATIONAL_CHARACTER
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.HAIR_COLOUR
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.HEIGHT
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.ISSUE_DATE
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.ISSUING_AUTHORITY
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.ISSUING_COUNTRY
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.ISSUING_JURISDICTION
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.NATIONALITY
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.PORTRAIT
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.PORTRAIT_CAPTURE_DATE
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.RESIDENT_ADDRESS
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.RESIDENT_CITY
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.RESIDENT_COUNTRY
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.RESIDENT_POSTAL_CODE
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.RESIDENT_STATE
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.SEX
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.SIGNATURE_USUAL_MARK
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.UN_DISTINGUISHING_SIGN
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.WEIGHT
import at.asitplus.wallet.lib.jws.ByteArrayBase64UrlSerializer
import io.github.aakira.napier.Napier
import io.matthewnelson.component.base64.encodeBase64ToCharArray
import kotlinx.datetime.LocalDate
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mDL (7.2.1)
 */
@Serializable
data class MobileDrivingLicence(
    @SerialName(FAMILY_NAME)
    val familyName: String,
    @SerialName(GIVEN_NAME)
    val givenName: String,
    @SerialName(BIRTH_DATE)
    val dateOfBirth: LocalDate? = null,
    @SerialName(ISSUE_DATE)
    val issueDate: LocalDate,
    @SerialName(EXPIRY_DATE)
    val expiryDate: LocalDate,
    @SerialName(ISSUING_COUNTRY)
    val issuingCountry: String? = null,
    @SerialName(ISSUING_AUTHORITY)
    val issuingAuthority: String? = null,
    @SerialName(DOCUMENT_NUMBER)
    val licenceNumber: String,
    @SerialName(PORTRAIT)
    @ByteString
    @Serializable(with = ByteArrayBase64UrlSerializer::class) // TODO and with cbor!?
    val portrait: ByteArray,
    @SerialName(DRIVING_PRIVILEGES)
    val drivingPrivileges: List<DrivingPrivilege>,
    @SerialName(UN_DISTINGUISHING_SIGN)
    val unDistinguishingSign: String? = null,
    @SerialName(ADMINISTRATIVE_NUMBER)
    val administrativeNumber: String? = null,
    @SerialName(SEX)
    @Serializable(with = IsoSexEnumSerializer::class)
    val sex: IsoSexEnum? = null,
    @SerialName(HEIGHT)
    val height: UInt? = null,
    @SerialName(WEIGHT)
    val weight: UInt? = null,
    @SerialName(EYE_COLOUR)
    val eyeColor: String? = null,
    @SerialName(HAIR_COLOUR)
    val hairColor: String? = null,
    @SerialName(BIRTH_PLACE)
    val placeOfBirth: String? = null,
    @SerialName(RESIDENT_ADDRESS)
    val placeOfResidence: String? = null,
    @SerialName(PORTRAIT_CAPTURE_DATE)
    val portraitImageTimestamp: LocalDate? = null,
    @SerialName(AGE_IN_YEARS)
    val ageInYears: UInt? = null,
    @SerialName(AGE_BIRTH_YEAR)
    val ageBirthYear: UInt? = null,
    @SerialName(AGE_OVER_18)
    val ageOver18: Boolean? = null,
    @SerialName(ISSUING_JURISDICTION)
    val issuingJurisdiction: String? = null,
    @SerialName(NATIONALITY)
    val nationality: String? = null,
    @SerialName(RESIDENT_CITY)
    val residentCity: String? = null,
    @SerialName(RESIDENT_STATE)
    val residentState: String? = null,
    @SerialName(RESIDENT_POSTAL_CODE)
    val residentPostalCode: String? = null,
    @SerialName(RESIDENT_COUNTRY)
    val residentCountry: String? = null,
    @SerialName(FAMILY_NAME_NATIONAL_CHARACTER)
    val familyNameNationalCharacters: String? = null,
    @SerialName(GIVEN_NAME_NATIONAL_CHARACTER)
    val givenNameNationalCharacters: String? = null,
    @ByteString
    @SerialName(SIGNATURE_USUAL_MARK)
    val signatureOrUsualMark: ByteArray? = null,
) {
    fun serialize() = cborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as MobileDrivingLicence

        if (familyName != other.familyName) return false
        if (givenName != other.givenName) return false
        if (dateOfBirth != other.dateOfBirth) return false
        if (issueDate != other.issueDate) return false
        if (expiryDate != other.expiryDate) return false
        if (issuingCountry != other.issuingCountry) return false
        if (issuingAuthority != other.issuingAuthority) return false
        if (licenceNumber != other.licenceNumber) return false
        if (!portrait.contentEquals(other.portrait)) return false
        if (drivingPrivileges != other.drivingPrivileges) return false
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
        if (ageOver18 != other.ageOver18) return false
        if (issuingJurisdiction != other.issuingJurisdiction) return false
        if (nationality != other.nationality) return false
        if (residentCity != other.residentCity) return false
        if (residentState != other.residentState) return false
        if (residentPostalCode != other.residentPostalCode) return false
        if (residentCountry != other.residentCountry) return false
        if (familyNameNationalCharacters != other.familyNameNationalCharacters) return false
        if (givenNameNationalCharacters != other.givenNameNationalCharacters) return false
        if (signatureOrUsualMark != null) {
            if (other.signatureOrUsualMark == null) return false
            if (!signatureOrUsualMark.contentEquals(other.signatureOrUsualMark)) return false
        } else if (other.signatureOrUsualMark != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = familyName.hashCode()
        result = 31 * result + givenName.hashCode()
        result = 31 * result + (dateOfBirth?.hashCode() ?: 0)
        result = 31 * result + issueDate.hashCode()
        result = 31 * result + expiryDate.hashCode()
        result = 31 * result + (issuingCountry?.hashCode() ?: 0)
        result = 31 * result + (issuingAuthority?.hashCode() ?: 0)
        result = 31 * result + licenceNumber.hashCode()
        result = 31 * result + portrait.contentHashCode()
        result = 31 * result + drivingPrivileges.hashCode()
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
        result = 31 * result + (ageOver18?.hashCode() ?: 0)
        result = 31 * result + (issuingJurisdiction?.hashCode() ?: 0)
        result = 31 * result + (nationality?.hashCode() ?: 0)
        result = 31 * result + (residentCity?.hashCode() ?: 0)
        result = 31 * result + (residentState?.hashCode() ?: 0)
        result = 31 * result + (residentPostalCode?.hashCode() ?: 0)
        result = 31 * result + (residentCountry?.hashCode() ?: 0)
        result = 31 * result + (familyNameNationalCharacters?.hashCode() ?: 0)
        result = 31 * result + (givenNameNationalCharacters?.hashCode() ?: 0)
        result = 31 * result + (signatureOrUsualMark?.contentHashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "MobileDrivingLicence(familyName='$familyName'," +
                " givenName='$givenName'," +
                " dateOfBirth=$dateOfBirth," +
                " issueDate=$issueDate," +
                " expiryDate=$expiryDate," +
                " issuingCountry='$issuingCountry'," +
                " issuingAuthority='$issuingAuthority'," +
                " licenceNumber='$licenceNumber'," +
                " portrait=${portrait.encodeBase64ToCharArray()}," +
                " drivingPrivileges=${drivingPrivileges}," +
                " unDistinguishingSign='$unDistinguishingSign'," +
                " administrativeNumber=$administrativeNumber," +
                " sex=$sex," +
                " height=$height," +
                " weight=$weight," +
                " eyeColor=$eyeColor," +
                " hairColor=$hairColor," +
                " placeOfBirth=$placeOfBirth," +
                " placeOfResidence=$placeOfResidence," +
                " portraitImageTimestamp=$portraitImageTimestamp," +
                " ageInYears=$ageInYears," +
                " ageBirthYear=$ageBirthYear," +
                " ageOver18=$ageOver18," +
                " issuingJurisdiction=$issuingJurisdiction," +
                " nationality=$nationality," +
                " residentCity=$residentCity," +
                " residentState=$residentState," +
                " residentPostalCode=$residentPostalCode," +
                " residentCountry=$residentCountry," +
                " familyNameNationalCharacters=$familyNameNationalCharacters," +
                " givenNameNationalCharacters=$givenNameNationalCharacters," +
                " signatureOrUsualMark=${signatureOrUsualMark?.encodeBase64ToCharArray()})"
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<MobileDrivingLicence>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}