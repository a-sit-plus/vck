package at.asitplus.wallet.eupid

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.eupidsdjwt.PlaceOfBirthSdJwt
import at.asitplus.wallet.lib.InternalHelpers.mandatoryElementsIso
import at.asitplus.wallet.lib.InternalHelpers.optionalElementsIso
import at.asitplus.wallet.lib.IsoNamespaceToElementIdentifierToItemValueSerializerMap
import at.asitplus.wallet.lib.JsonValueEncoder
import at.asitplus.wallet.lib.data.LocalDateOrInstantSerializer
import at.asitplus.wallet.sdjwt.CredentialFormatEnum
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationList
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDefinition
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocument
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataVckExtensions
import at.asitplus.wallet.sdjwt.SdJwtVcType
import kotlinx.datetime.LocalDate
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.encodeToJsonElement

/** `eu.europa.ec.eudi.pid.1` */
const val EU_PID_DOCTYPE: String = "eu.europa.ec.eudi.pid.1"

/** Canonical hosted location of [EuPidMetadataDocument], used as the resolved scheme's `schemaUri`. */
const val EU_PID_METADATA_URL: String =
    "https://raw.githubusercontent.com/a-sit-plus/credentials-collection/main/eu-pid.json"

val EuPidMetadataDocument: Pair<SdJwtVcType, SdJwtTypeMetadataDocument> =
    SdJwtVcType("EuPid2023") to SdJwtTypeMetadataDocument(
        originalBytes = ByteArray(0),
        definition = SdJwtTypeMetadataDefinition(
            vct = SdJwtVcType("EuPid2023"),
            claims = SdJwtTypeMetadataClaimInformationList(
                mandatoryElementsIso(
                    EU_PID_DOCTYPE, // yep, namespace is the same as docType
                    EuPidDataElements.FAMILY_NAME,
                    EuPidDataElements.GIVEN_NAME,
                    EuPidDataElements.BIRTH_DATE,
                    EuPidDataElements.NATIONALITY,
                    EuPidDataElements.EXPIRY_DATE,
                    EuPidDataElements.ISSUING_AUTHORITY,
                    EuPidDataElements.ISSUING_COUNTRY,
                ) + optionalElementsIso(
                    EU_PID_DOCTYPE, // yep, namespace is the same as docType
                    EuPidDataElements.FAMILY_NAME_BIRTH,
                    EuPidDataElements.GIVEN_NAME_BIRTH,
                    EuPidDataElements.PLACE_OF_BIRTH,
                    EuPidDataElements.RESIDENT_ADDRESS,
                    EuPidDataElements.RESIDENT_COUNTRY,
                    EuPidDataElements.RESIDENT_STATE,
                    EuPidDataElements.RESIDENT_CITY,
                    EuPidDataElements.RESIDENT_POSTAL_CODE,
                    EuPidDataElements.RESIDENT_STREET,
                    EuPidDataElements.RESIDENT_HOUSE_NUMBER,
                    EuPidDataElements.SEX,
                    EuPidDataElements.ISSUANCE_DATE,
                    EuPidDataElements.DOCUMENT_NUMBER,
                    EuPidDataElements.ISSUING_JURISDICTION,
                    EuPidDataElements.PERSONAL_ADMINISTRATIVE_NUMBER,
                    EuPidDataElements.PORTRAIT,
                    EuPidDataElements.EMAIL_ADDRESS,
                    EuPidDataElements.MOBILE_PHONE_NUMBER,
                    EuPidDataElements.TRUST_ANCHOR,
                    EuPidDataElements.LOCATION_STATUS,
                )
            ),
            vckExtensions = SdJwtTypeMetadataVckExtensions(
                format = CredentialFormatEnum.MSO_MDOC,
                isoDocType = EU_PID_DOCTYPE,
                isoNamespace = EU_PID_DOCTYPE // yep, namespace is the same as docType
            )
        )
    )
val EuPidItemValueSerializerMap: IsoNamespaceToElementIdentifierToItemValueSerializerMap = mapOf(
    EU_PID_DOCTYPE to mapOf(
        EuPidDataElements.BIRTH_DATE to LocalDate.serializer(),
        EuPidDataElements.SEX to UInt.serializer(),
        EuPidDataElements.NATIONALITY to SetSerializer(String.serializer()),
        EuPidDataElements.ISSUANCE_DATE to LocalDateOrInstantSerializer,
        EuPidDataElements.EXPIRY_DATE to LocalDateOrInstantSerializer,
        EuPidDataElements.PORTRAIT to ByteArraySerializer(),
        EuPidDataElements.PLACE_OF_BIRTH to PlaceOfBirth.serializer(),
    )
)

val EuPidJsonValueEncoder: JsonValueEncoder = {
    when (it) {
        is IsoIec5218Gender -> joseCompliantSerializer.encodeToJsonElement(it)
        is PlaceOfBirthSdJwt -> joseCompliantSerializer.encodeToJsonElement(it)
        is PlaceOfBirth -> joseCompliantSerializer.encodeToJsonElement(it)
        else -> null
    }
}