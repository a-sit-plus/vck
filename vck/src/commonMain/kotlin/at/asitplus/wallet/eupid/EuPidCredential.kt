package at.asitplus.wallet.eupid

import at.asitplus.catchingUnwrapped
import at.asitplus.wallet.lib.data.LocalDateOrInstant
import at.asitplus.wallet.lib.data.toUIntFromJava
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.jvm.JvmOverloads
import kotlinx.datetime.LocalDate
import kotlinx.datetime.serializers.LocalDateIso8601Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive


/**
 * PID scheme according to
 * [PID Rulebook](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md)
 * from 2025-10-02.
 */
@Serializable
@SerialName("EuPid2023")
data class EuPidCredential(

    @SerialName("id")
    val id: String,

    /** Current last name(s) or surname(s) of the user to whom the person identification data relates. */
    @SerialName(EuPidDataElements.FAMILY_NAME)
    val familyName: String,

    /** Current first name(s), including middle name(s) where applicable, of the user to whom the person identification data relates. */
    @SerialName(EuPidDataElements.GIVEN_NAME)
    val givenName: String,

    /** Day, month, and year on which the user to whom the person identification data relates was born. */
    @SerialName(EuPidDataElements.BIRTH_DATE)
    @Serializable(with = LocalDateIso8601Serializer::class)
    val birthDate: LocalDate,

    /** Last name(s) or surname(s) of the User to whom the person identification data relates at the time of birth. */
    @SerialName(EuPidDataElements.FAMILY_NAME_BIRTH)
    val familyNameBirth: String? = null,

    /** First name(s), including middle name(s), of the User to whom the person identification data relates at the time of birth. */
    @SerialName(EuPidDataElements.GIVEN_NAME_BIRTH)
    val givenNameBirth: String? = null,

    /** See [PlaceOfBirth]. At least one of the values shall be present. */
    @SerialName(EuPidDataElements.PLACE_OF_BIRTH)
    val placeOfBirth: PlaceOfBirth? = null,

    /**
     * The full address of the place where the user to whom the person identification data relates currently resides or
     * can be contacted (street name, house number, city etc.).
     */
    @SerialName(EuPidDataElements.RESIDENT_ADDRESS)
    val residentAddress: String? = null,

    /** The country where the user to whom the person identification data relates currently resides, as an alpha-2
     * country code as specified in ISO 3166-1. */
    @SerialName(EuPidDataElements.RESIDENT_COUNTRY)
    val residentCountry: String? = null,

    /** The state, province, district, or local area where the user to whom the person identification data relates
     * currently resides. */
    @SerialName(EuPidDataElements.RESIDENT_STATE)
    val residentState: String? = null,

    /** The municipality, city, town, or village where the user to whom the person identification data relates currently
     *  resides. */
    @SerialName(EuPidDataElements.RESIDENT_CITY)
    val residentCity: String? = null,

    /** The postal code of the place where the user to whom the person identification data relates currently resides. */
    @SerialName(EuPidDataElements.RESIDENT_POSTAL_CODE)
    val residentPostalCode: String? = null,

    /** The name of the street where the user to whom the person identification data relates currently resides. */
    @SerialName(EuPidDataElements.RESIDENT_STREET)
    val residentStreet: String? = null,

    /** The house number where the user to whom the person identification data relates currently resides, including any
     *  affix or suffix. */
    @SerialName(EuPidDataElements.RESIDENT_HOUSE_NUMBER)
    val residentHouseNumber: String? = null,

    /** Values shall be one of the following: 0 = not known; 1 = male; 2 = female; 3 = other; 4 = inter; 5 = diverse;
     * 6 = open; 9 = not applicable. For values 0, 1, 2 and 9, ISO/IEC 5218 applies. */
    @SerialName(EuPidDataElements.SEX)
    val sex: UInt? = null,

    /** One or more alpha-2 country codes as specified in ISO 3166-1, representing the nationality of the user to whom
     *  the person identification data relates.
     *  Before ARF 1.5.0, this has been a single string, now it may contain more than one entry. */
    @SerialName(EuPidDataElements.NATIONALITY)
    val nationalityElement: JsonElement? = null,

    /** Date (and if possible time) when the person identification data was issued and/or the administrative validity period of the person identification data began. */
    @SerialName(EuPidDataElements.ISSUANCE_DATE)
    val issuanceDate: LocalDateOrInstant,

    /** Date (and if possible time) when the person identification data will expire. */
    @SerialName(EuPidDataElements.EXPIRY_DATE)
    val expiryDate: LocalDateOrInstant,

    /**
     * Name of the administrative authority that has issued this PID instance, or
     * the ISO 3166 Alpha-2 country code of the respective Member State if
     * there is no separate authority authorized to issue PIDs.
     */
    @SerialName(EuPidDataElements.ISSUING_AUTHORITY)
    val issuingAuthority: String,

    /** A number for the PID, assigned by the PID Provider. */
    @SerialName(EuPidDataElements.DOCUMENT_NUMBER)
    val documentNumber: String? = null,

    /** Alpha-2 country code, as defined in ISO 3166-1, of the PID Provider's country or territory. */
    @SerialName(EuPidDataElements.ISSUING_COUNTRY)
    val issuingCountry: String,

    /**
     * Country subdivision code of the jurisdiction that issued the PID, as
     * defined in ISO 3166-2:2020, Clause 8. The first part of the code SHALL
     * be the same as the value for [issuingCountry].
     */
    @SerialName(EuPidDataElements.ISSUING_JURISDICTION)
    val issuingJurisdiction: String? = null,

    /**
     * A value assigned to the natural person that is unique among all personal administrative numbers issued by the
     * provider of person identification data. Where Member States opt to include this attribute, they shall
     * describe in their electronic identification schemes under which the person identification data is issued,
     * the policy that they apply to the values of this attribute, including, where applicable, specific conditions
     * for the processing of this value.
     */
    @SerialName(EuPidDataElements.PERSONAL_ADMINISTRATIVE_NUMBER)
    val personalAdministrativeNumber: String? = null,

    /** Facial image of the wallet user compliant with ISO 19794-5 or ISO 39794 specifications. */
    @SerialName(EuPidDataElements.PORTRAIT)
    val portrait: ByteArray? = null,

    /** Electronic mail address of the user to whom the person identification data relates, in conformance with [RFC 5322]. */
    @SerialName(EuPidDataElements.EMAIL_ADDRESS)
    val emailAddress: String? = null,

    /** Mobile telephone number of the User to whom the person identification data relates, starting with the '+'
     * symbol as the international code prefix and the country code, followed by numbers only. */
    @SerialName(EuPidDataElements.MOBILE_PHONE_NUMBER)
    val mobilePhoneNumber: String? = null,

    /** This attribute indicates at least the URL at which a machine-readable version of the trust anchor to be used for verifying the PID can be found or looked up */
    @SerialName(EuPidDataElements.TRUST_ANCHOR)
    val trustAnchor: String? = null,

    /** The location of validity status information on the person identification data where the providers of person identification data revoke person identification data. */
    @SerialName(EuPidDataElements.LOCATION_STATUS)
    val locationStatus: String? = null,
) {
    /**
     * Java-safe constructor: Java can't call the primary constructor, because it takes the value class [UInt].
     */
    @JvmOverloads
    internal constructor(
        id: String,
        familyName: String,
        givenName: String,
        birthDate: LocalDate,
        familyNameBirth: String? = null,
        givenNameBirth: String? = null,
        placeOfBirth: PlaceOfBirth? = null,
        residentAddress: String? = null,
        residentCountry: String? = null,
        residentState: String? = null,
        residentCity: String? = null,
        residentPostalCode: String? = null,
        residentStreet: String? = null,
        residentHouseNumber: String? = null,
        sex: Long? = null,
        nationalityElement: JsonElement? = null,
        issuanceDate: LocalDateOrInstant,
        expiryDate: LocalDateOrInstant,
        issuingAuthority: String,
        documentNumber: String? = null,
        issuingCountry: String,
        issuingJurisdiction: String? = null,
        personalAdministrativeNumber: String? = null,
        portrait: ByteArray? = null,
        emailAddress: String? = null,
        mobilePhoneNumber: String? = null,
        trustAnchor: String? = null,
        locationStatus: String? = null,
    ) : this(
        id = id,
        familyName = familyName,
        givenName = givenName,
        birthDate = birthDate,
        familyNameBirth = familyNameBirth,
        givenNameBirth = givenNameBirth,
        placeOfBirth = placeOfBirth,
        residentAddress = residentAddress,
        residentCountry = residentCountry,
        residentState = residentState,
        residentCity = residentCity,
        residentPostalCode = residentPostalCode,
        residentStreet = residentStreet,
        residentHouseNumber = residentHouseNumber,
        sex = sex?.toUIntFromJava("sex"),
        nationalityElement = nationalityElement,
        issuanceDate = issuanceDate,
        expiryDate = expiryDate,
        issuingAuthority = issuingAuthority,
        documentNumber = documentNumber,
        issuingCountry = issuingCountry,
        issuingJurisdiction = issuingJurisdiction,
        personalAdministrativeNumber = personalAdministrativeNumber,
        portrait = portrait,
        emailAddress = emailAddress,
        mobilePhoneNumber = mobilePhoneNumber,
        trustAnchor = trustAnchor,
        locationStatus = locationStatus,
    )

    /** Java-safe accessor for [sex]. */
    val sexAsLong: Long?
        get() = sex?.toLong()

    /** Values shall be one of the following: 0 = not known; 1 = male; 2 = female; 3 = other; 4 = inter; 5 = diverse;
     * 6 = open; 9 = not applicable. For values 0, 1, 2 and 9, ISO/IEC 5218 applies. */
    val sexAsEnum: IsoIec5218Gender? by lazy {
        sex?.let { IsoIec5218Gender.entries.firstOrNull { it.code == sex } }
    }

    /** One or more alpha-2 country codes as specified in ISO 3166-1, representing the nationality of the user to whom
     *  the person identification data relates.*/
    val nationality: String? by lazy {
        nationalityElement?.let { catchingUnwrapped { it.jsonPrimitive.content }.getOrNull() }
    }

    /** One or more alpha-2 country codes as specified in ISO 3166-1, representing the nationality of the user to whom
     *  the person identification data relates.*/
    val nationalities: Collection<String>? by lazy {
        nationalityElement?.let { catchingUnwrapped { it.jsonArray.map { it.jsonPrimitive.content } }.getOrNull() }
    }


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as EuPidCredential

        if (id != other.id) return false
        if (familyName != other.familyName) return false
        if (givenName != other.givenName) return false
        if (birthDate != other.birthDate) return false
        if (familyNameBirth != other.familyNameBirth) return false
        if (givenNameBirth != other.givenNameBirth) return false
        if (placeOfBirth != other.placeOfBirth) return false
        if (residentAddress != other.residentAddress) return false
        if (residentCountry != other.residentCountry) return false
        if (residentState != other.residentState) return false
        if (residentCity != other.residentCity) return false
        if (residentPostalCode != other.residentPostalCode) return false
        if (residentStreet != other.residentStreet) return false
        if (residentHouseNumber != other.residentHouseNumber) return false
        if (sex != other.sex) return false
        if (nationalityElement != other.nationalityElement) return false
        if (issuanceDate != other.issuanceDate) return false
        if (expiryDate != other.expiryDate) return false
        if (issuingAuthority != other.issuingAuthority) return false
        if (documentNumber != other.documentNumber) return false
        if (issuingCountry != other.issuingCountry) return false
        if (issuingJurisdiction != other.issuingJurisdiction) return false
        if (personalAdministrativeNumber != other.personalAdministrativeNumber) return false
        if (!portrait.contentEquals(other.portrait)) return false
        if (emailAddress != other.emailAddress) return false
        if (mobilePhoneNumber != other.mobilePhoneNumber) return false
        if (trustAnchor != other.trustAnchor) return false
        if (locationStatus != other.locationStatus) return false
        if (sexAsEnum != other.sexAsEnum) return false
        if (nationality != other.nationality) return false
        if (nationalities != other.nationalities) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + familyName.hashCode()
        result = 31 * result + givenName.hashCode()
        result = 31 * result + birthDate.hashCode()
        result = 31 * result + (familyNameBirth?.hashCode() ?: 0)
        result = 31 * result + (givenNameBirth?.hashCode() ?: 0)
        result = 31 * result + (placeOfBirth?.hashCode() ?: 0)
        result = 31 * result + (residentAddress?.hashCode() ?: 0)
        result = 31 * result + (residentCountry?.hashCode() ?: 0)
        result = 31 * result + (residentState?.hashCode() ?: 0)
        result = 31 * result + (residentCity?.hashCode() ?: 0)
        result = 31 * result + (residentPostalCode?.hashCode() ?: 0)
        result = 31 * result + (residentStreet?.hashCode() ?: 0)
        result = 31 * result + (residentHouseNumber?.hashCode() ?: 0)
        result = 31 * result + (sex?.hashCode() ?: 0)
        result = 31 * result + (nationalityElement?.hashCode() ?: 0)
        result = 31 * result + issuanceDate.hashCode()
        result = 31 * result + expiryDate.hashCode()
        result = 31 * result + issuingAuthority.hashCode()
        result = 31 * result + (documentNumber?.hashCode() ?: 0)
        result = 31 * result + issuingCountry.hashCode()
        result = 31 * result + (issuingJurisdiction?.hashCode() ?: 0)
        result = 31 * result + (personalAdministrativeNumber?.hashCode() ?: 0)
        result = 31 * result + (portrait?.contentHashCode() ?: 0)
        result = 31 * result + (emailAddress?.hashCode() ?: 0)
        result = 31 * result + (mobilePhoneNumber?.hashCode() ?: 0)
        result = 31 * result + (trustAnchor?.hashCode() ?: 0)
        result = 31 * result + (locationStatus?.hashCode() ?: 0)
        result = 31 * result + (sexAsEnum?.hashCode() ?: 0)
        result = 31 * result + (nationality?.hashCode() ?: 0)
        result = 31 * result + (nationalities?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "EuPidCredential(" +
                "id='$id', " +
                "familyName='$familyName', " +
                "givenName='$givenName', " +
                "birthDate=$birthDate, " +
                "familyNameBirth=$familyNameBirth, " +
                "givenNameBirth=$givenNameBirth, " +
                "placeOfBirth=$placeOfBirth, " +
                "residentAddress=$residentAddress, " +
                "residentCountry=$residentCountry, " +
                "residentState=$residentState, " +
                "residentCity=$residentCity, " +
                "residentPostalCode=$residentPostalCode, " +
                "residentStreet=$residentStreet, " +
                "residentHouseNumber=$residentHouseNumber, " +
                "sex=$sex, " +
                "nationality=$nationality, " +
                "issuanceDate=$issuanceDate, " +
                "expiryDate=$expiryDate, " +
                "issuingAuthority='$issuingAuthority', " +
                "documentNumber=$documentNumber, " +
                "issuingCountry='$issuingCountry', " +
                "issuingJurisdiction=$issuingJurisdiction, " +
                "personalAdministrativeNumber=$personalAdministrativeNumber, " +
                "portrait=${portrait?.encodeToString(Base64())}, " +
                "emailAddress=$emailAddress, " +
                "mobilePhoneNumber=$mobilePhoneNumber, " +
                "trustAnchor=$trustAnchor, " +
                "locationStatus=$locationStatus" +
                ")"
    }

}

/** At least one of the values shall be present. */
@Serializable
data class PlaceOfBirth(
    /** The country where the PID User was born, as an Alpha-2 country code as specified in ISO 3166-1. */
    @SerialName(EuPidDataElements.PlaceOfBirth.COUNTRY)
    val country: String? = null,

    /** The state, province, district, or local area where the PID User was born. */
    @SerialName(EuPidDataElements.PlaceOfBirth.REGION)
    val region: String? = null,

    /** The municipality, city, town, or village where the PID User was born. */
    @SerialName(EuPidDataElements.PlaceOfBirth.LOCALITY)
    val locality: String? = null,
)
