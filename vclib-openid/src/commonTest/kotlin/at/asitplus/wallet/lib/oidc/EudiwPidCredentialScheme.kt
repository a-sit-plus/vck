package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.ConstantIndex

object EudiwPidCredentialScheme : ConstantIndex.CredentialScheme {
    override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/EudiwPid1.json"
    override val vcType: String = "EudiwPid1"
    override val isoNamespace: String = "eu.europa.ec.eudiw.pid.1"
    override val isoDocType: String = "eu.europa.ec.eudiw.pid.1"
    override val claimNames: Collection<String> = listOf(
        Attributes.FAMILY_NAME,
        Attributes.GIVEN_NAME,
        Attributes.BIRTH_DATE,

        Attributes.AGE_OVER_18,
        Attributes.AGE_IN_YEARS,
        Attributes.AGE_BIRTH_YEAR,
        Attributes.FAMILY_NAME_BIRTH,
        Attributes.GIVEN_NAME_BIRTH,
        Attributes.BIRTH_PLACE,
        Attributes.BIRTH_COUNTRY,
        Attributes.BIRTH_STATE,
        Attributes.BIRTH_CITY,

        Attributes.RESIDENT_ADDRESS,
        Attributes.RESIDENT_COUNTRY,
        Attributes.RESIDENT_STATE,
        Attributes.RESIDENT_CITY,
        Attributes.RESIDENT_POSTAL_CODE,
        Attributes.RESIDENT_STREET,
        Attributes.RESIDENT_HOUSE_NUMBER,

        Attributes.GENDER,
        Attributes.NATIONALITY,

        Attributes.EXPIRY_DATE,
        Attributes.ISSUANCE_DATE,
        Attributes.ISSUING_AUTHORITY,
        Attributes.DOCUMENT_NUMBER,
        Attributes.ADMINISTRATIVE_NUMBER,
        Attributes.ISSUING_COUNTRY,
        Attributes.ISSUING_JURISTICTION,
    )
    val requiredClaimNames: Collection<String> = listOf(
        Attributes.FAMILY_NAME,
        Attributes.GIVEN_NAME,
        Attributes.BIRTH_DATE
    )

    object Attributes {
        const val FAMILY_NAME = "family_name"
        const val GIVEN_NAME = "given_name"
        const val BIRTH_DATE = "birth_date"

        const val AGE_OVER_18 = "age_over_18"
        const val AGE_IN_YEARS = "age_in_years"
        const val AGE_BIRTH_YEAR = "age_birth_year"
        const val FAMILY_NAME_BIRTH = "family_name_birth"
        const val GIVEN_NAME_BIRTH = "given_name_birth"

        const val BIRTH_PLACE = "birth_place"
        const val BIRTH_COUNTRY = "birth_country"
        const val BIRTH_STATE = "birth_state"
        const val BIRTH_CITY = "birth_city"

        const val RESIDENT_ADDRESS = "resident_address"
        const val RESIDENT_COUNTRY = "resident_country"
        const val RESIDENT_STATE = "resident_state"
        const val RESIDENT_CITY = "resident_city"
        const val RESIDENT_POSTAL_CODE = "resident_postal_code"
        const val RESIDENT_STREET = "resident_street"
        const val RESIDENT_HOUSE_NUMBER = "resident_house_number"

        const val GENDER = "gender"
        const val NATIONALITY = "nationality"

        const val EXPIRY_DATE = "expiry_date"
        const val ISSUANCE_DATE = "issuance_date"
        const val ISSUING_AUTHORITY = "issuing_authority"
        const val DOCUMENT_NUMBER = "document_number"
        const val ADMINISTRATIVE_NUMBER = "administrative_number"
        const val ISSUING_COUNTRY = "issuing_country"
        const val ISSUING_JURISTICTION = "issuing_jurisdiction"
    }
}