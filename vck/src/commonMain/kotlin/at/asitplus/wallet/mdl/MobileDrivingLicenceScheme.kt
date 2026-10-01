package at.asitplus.wallet.mdl

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.InternalHelpers.mandatoryElementsIso
import at.asitplus.wallet.lib.InternalHelpers.optionalElementsIso
import at.asitplus.wallet.lib.IsoNamespaceToElementIdentifierToItemValueSerializerMap
import at.asitplus.wallet.lib.JsonValueEncoder
import at.asitplus.wallet.sdjwt.CredentialFormatEnum
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationList
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDefinition
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocument
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataVckExtensions
import at.asitplus.wallet.sdjwt.SdJwtVcType
import kotlinx.datetime.LocalDate
import kotlinx.serialization.builtins.ArraySerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.encodeToJsonElement


/** `org.iso.18013.5.1.mDL` */
const val MDL_DOCTYPE: String = "org.iso.18013.5.1.mDL"

/** `org.iso.18013.5.1` */
const val MDL_NAMESPACE: String = "org.iso.18013.5.1"

/** Canonical hosted location of [MobileDrivingLicenceMetadataDocument], used as the resolved scheme's `schemaUri`. */
const val MDL_METADATA_URL: String =
    "https://raw.githubusercontent.com/a-sit-plus/credentials-collection/main/mdl.json"

val MobileDrivingLicenceMetadataDocument: Pair<SdJwtVcType, SdJwtTypeMetadataDocument> =
    SdJwtVcType(MDL_DOCTYPE) to SdJwtTypeMetadataDocument(
        originalBytes = ByteArray(0),
        definition = SdJwtTypeMetadataDefinition(
            vct = SdJwtVcType(MDL_DOCTYPE),
            claims = SdJwtTypeMetadataClaimInformationList(
                mandatoryElementsIso(
                    MDL_NAMESPACE,
                    MobileDrivingLicenceDataElements.FAMILY_NAME,
                    MobileDrivingLicenceDataElements.GIVEN_NAME,
                    MobileDrivingLicenceDataElements.BIRTH_DATE,
                    MobileDrivingLicenceDataElements.ISSUE_DATE,
                    MobileDrivingLicenceDataElements.EXPIRY_DATE,
                    MobileDrivingLicenceDataElements.ISSUING_COUNTRY,
                    MobileDrivingLicenceDataElements.ISSUING_AUTHORITY,
                    MobileDrivingLicenceDataElements.DOCUMENT_NUMBER,
                    MobileDrivingLicenceDataElements.PORTRAIT,
                    MobileDrivingLicenceDataElements.DRIVING_PRIVILEGES,
                    MobileDrivingLicenceDataElements.UN_DISTINGUISHING_SIGN
                ) + optionalElementsIso(
                    MDL_NAMESPACE,
                    MobileDrivingLicenceDataElements.ADMINISTRATIVE_NUMBER,
                    MobileDrivingLicenceDataElements.SEX,
                    MobileDrivingLicenceDataElements.HEIGHT,
                    MobileDrivingLicenceDataElements.WEIGHT,
                    MobileDrivingLicenceDataElements.EYE_COLOUR,
                    MobileDrivingLicenceDataElements.HAIR_COLOUR,
                    MobileDrivingLicenceDataElements.BIRTH_PLACE,
                    MobileDrivingLicenceDataElements.RESIDENT_ADDRESS,
                    MobileDrivingLicenceDataElements.PORTRAIT_CAPTURE_DATE,
                    MobileDrivingLicenceDataElements.AGE_IN_YEARS,
                    MobileDrivingLicenceDataElements.AGE_BIRTH_YEAR,
                    MobileDrivingLicenceDataElements.AGE_OVER_12,
                    MobileDrivingLicenceDataElements.AGE_OVER_13,
                    MobileDrivingLicenceDataElements.AGE_OVER_14,
                    MobileDrivingLicenceDataElements.AGE_OVER_16,
                    MobileDrivingLicenceDataElements.AGE_OVER_18,
                    MobileDrivingLicenceDataElements.AGE_OVER_21,
                    MobileDrivingLicenceDataElements.AGE_OVER_25,
                    MobileDrivingLicenceDataElements.AGE_OVER_60,
                    MobileDrivingLicenceDataElements.AGE_OVER_62,
                    MobileDrivingLicenceDataElements.AGE_OVER_65,
                    MobileDrivingLicenceDataElements.AGE_OVER_68,
                    MobileDrivingLicenceDataElements.ISSUING_JURISDICTION,
                    MobileDrivingLicenceDataElements.NATIONALITY,
                    MobileDrivingLicenceDataElements.RESIDENT_CITY,
                    MobileDrivingLicenceDataElements.RESIDENT_STATE,
                    MobileDrivingLicenceDataElements.RESIDENT_POSTAL_CODE,
                    MobileDrivingLicenceDataElements.RESIDENT_COUNTRY,
                    MobileDrivingLicenceDataElements.FAMILY_NAME_NATIONAL_CHARACTER,
                    MobileDrivingLicenceDataElements.GIVEN_NAME_NATIONAL_CHARACTER,
                    MobileDrivingLicenceDataElements.SIGNATURE_USUAL_MARK,
                    MobileDrivingLicenceDataElements.BIOMETRIC_TEMPLATE_FACE,
                    MobileDrivingLicenceDataElements.BIOMETRIC_TEMPLATE_FINGER,
                    MobileDrivingLicenceDataElements.BIOMETRIC_TEMPLATE_SIGNATURE_SIGN,
                    MobileDrivingLicenceDataElements.BIOMETRIC_TEMPLATE_IRIS
                )
            ),
            vckExtensions = SdJwtTypeMetadataVckExtensions(
                format = CredentialFormatEnum.MSO_MDOC,
                isoDocType = MDL_DOCTYPE,
                isoNamespace = MDL_NAMESPACE
            )
        )
    )

val MobileDrivingLicenceItemValueSerializerMap: IsoNamespaceToElementIdentifierToItemValueSerializerMap = mapOf(
    MDL_NAMESPACE to mapOf(
        MobileDrivingLicenceDataElements.BIRTH_DATE to LocalDate.serializer(),
        MobileDrivingLicenceDataElements.ISSUE_DATE to LocalDate.serializer(),
        MobileDrivingLicenceDataElements.EXPIRY_DATE to LocalDate.serializer(),
        MobileDrivingLicenceDataElements.PORTRAIT to ByteArraySerializer(),
        MobileDrivingLicenceDataElements.DRIVING_PRIVILEGES to ArraySerializer(DrivingPrivilege.serializer()),
        MobileDrivingLicenceDataElements.SEX to IsoSexEnumSerializer,
        MobileDrivingLicenceDataElements.HEIGHT to UInt.serializer(),
        MobileDrivingLicenceDataElements.WEIGHT to UInt.serializer(),
        MobileDrivingLicenceDataElements.PORTRAIT_CAPTURE_DATE to LocalDate.serializer(),
        MobileDrivingLicenceDataElements.AGE_IN_YEARS to UInt.serializer(),
        MobileDrivingLicenceDataElements.AGE_BIRTH_YEAR to UInt.serializer(),
        MobileDrivingLicenceDataElements.SIGNATURE_USUAL_MARK to ByteArraySerializer(),
        MobileDrivingLicenceDataElements.AGE_OVER_12 to Boolean.serializer(),
        MobileDrivingLicenceDataElements.AGE_OVER_13 to Boolean.serializer(),
        MobileDrivingLicenceDataElements.AGE_OVER_14 to Boolean.serializer(),
        MobileDrivingLicenceDataElements.AGE_OVER_16 to Boolean.serializer(),
        MobileDrivingLicenceDataElements.AGE_OVER_18 to Boolean.serializer(),
        MobileDrivingLicenceDataElements.AGE_OVER_21 to Boolean.serializer(),
        MobileDrivingLicenceDataElements.AGE_OVER_25 to Boolean.serializer(),
        MobileDrivingLicenceDataElements.AGE_OVER_60 to Boolean.serializer(),
        MobileDrivingLicenceDataElements.AGE_OVER_62 to Boolean.serializer(),
        MobileDrivingLicenceDataElements.AGE_OVER_65 to Boolean.serializer(),
        MobileDrivingLicenceDataElements.AGE_OVER_68 to Boolean.serializer(),
        MobileDrivingLicenceDataElements.BIOMETRIC_TEMPLATE_FACE to ByteArraySerializer(),
        MobileDrivingLicenceDataElements.BIOMETRIC_TEMPLATE_FINGER to ByteArraySerializer(),
        MobileDrivingLicenceDataElements.BIOMETRIC_TEMPLATE_SIGNATURE_SIGN to ByteArraySerializer(),
        MobileDrivingLicenceDataElements.BIOMETRIC_TEMPLATE_IRIS to ByteArraySerializer(),
    )
)

val MobileDrivingLicenceJsonValueEncoder: JsonValueEncoder = {
    when (it) {
        is DrivingPrivilege -> joseCompliantSerializer.encodeToJsonElement(it)
        else -> null
    }
}