@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.wallet.lib.iso

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
    @SerialName("family_name")
    val familyName: String,
    @SerialName("given_name")
    val givenName: String,
    @SerialName("birth_date")
    val dateOfBirth: LocalDate,
    @SerialName("issue_date")
    val issueDate: LocalDate,
    @SerialName("expiry_date")
    val expiryDate: LocalDate,
    @SerialName("issuing_country")
    val issuingCountry: String,
    @SerialName("issuing_authority")
    val issuingAuthority: String,
    @SerialName("document_number")
    val licenceNumber: String,
    @SerialName("portrait")
    @ByteString
    val portrait: ByteArray,
    @SerialName("driving_privileges")
    val drivingPrivileges: Array<DrivingPrivilege>,
    @SerialName("un_distinguishing_sign")
    val unDistinguishingSign: String,
    @SerialName("administrative_number")
    val administrativeNumber: String? = null,
    @SerialName("sex")
    @Serializable(with = IsoSexEnumSerializer::class)
    val sex: IsoSexEnum? = null,
    @SerialName("height")
    val height: UInt? = null,
    @SerialName("weight")
    val weight: UInt? = null,
    @SerialName("eye_colour")
    val eyeColor: String? = null,
    @SerialName("hair_colour")
    val hairColor: String? = null,
    @SerialName("birth_place")
    val placeOfBirth: String? = null,
    @SerialName("resident_address")
    val placeOfResidence: String? = null,
    @SerialName("portrait_capture_date")
    val portraitImageTimestamp: LocalDate? = null,
    @SerialName("age_in_years")
    val ageInYears: UInt? = null,
    @SerialName("age_birth_year")
    val ageBirthYear: UInt? = null,
    @SerialName("age_over_18")
    val ageOver18: Boolean? = null,
    @SerialName("issuing_jurisdiction")
    val issuingJurisdiction: String? = null,
    @SerialName("nationality")
    val nationality: String? = null,
    @SerialName("resident_city")
    val residentCity: String? = null,
    @SerialName("resident_state")
    val residentState: String? = null,
    @SerialName("resident_postal_code")
    val residentPostalCode: String? = null,
    @SerialName("resident_country")
    val residentCountry: String? = null,
    @SerialName("family_name_national_character")
    val familyNameNationalCharacters: String? = null,
    @SerialName("given_name_national_character")
    val givenNameNationalCharacters: String? = null,
    @ByteString
    @SerialName("signature_usual_mark")
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
        result = 31 * result + dateOfBirth.hashCode()
        result = 31 * result + issueDate.hashCode()
        result = 31 * result + expiryDate.hashCode()
        result = 31 * result + issuingCountry.hashCode()
        result = 31 * result + issuingAuthority.hashCode()
        result = 31 * result + licenceNumber.hashCode()
        result = 31 * result + portrait.contentHashCode()
        result = 31 * result + drivingPrivileges.contentHashCode()
        result = 31 * result + unDistinguishingSign.hashCode()
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
                " drivingPrivileges=${drivingPrivileges.contentToString()}," +
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
