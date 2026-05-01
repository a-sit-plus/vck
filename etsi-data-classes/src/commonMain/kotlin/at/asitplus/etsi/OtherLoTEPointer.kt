package at.asitplus.etsi

import at.asitplus.rfc.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * 2026-04-23
 * https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf
 * 6.3.13 Pointers to other LoTEs
 * Description:
 * The PointersToOtherLoTE component references any relevant list of trusted entities or any relevant list of lists of
 * trusted entities.
 * ETSI
 * ETSI TS 119 602 V1.1.1 (2025-11)23
 * Format:
 * The PointersToOtherLoTE component shall contain a sequence of one or more OtherLoTEPointer elements,
 * each OtherLoTEPointer element giving:
 * a) a LoTELocation element containing the URI of the machine processable format of another LoTE;
 * b) one or more ServiceDigitalIdentity element, all representing the issuer of the LoTE pointed to,
 * formatted as specified in clause 6.6.3; and
 * c) additional information as a set of LoTE Qualifiers: LoTE Type, as defined in clause 6.3.3; Scheme operator
 * name, as defined in clause 6.3.4; optionally the Scheme type/community/rules, as defined in clause 6.3.9;
 * Scheme territory, as defined in clause 6.3.10; and Mime type.
 * Semantics:
 * More than one digital identity may be used to help the management of the pointed-to list signing process (e.g. in case of
 * expiration/substitution of pointed-to list signing keys or more than a single signing key is allowed to sign this list).
 * One of such digital identities shall allow successful authentication of the pointed-to list before its use.
 */
@Serializable
data class OtherLoTEPointer(
    @SerialName(SerialNames.LOTE_LOCATION)
    val loteLocation: Rfc3986UniformResourceIdentifier,
    @SerialName(SerialNames.SERVICE_DIGITAL_IDENTITY)
    val serviceDigitalIdentity: List<ServiceDigitalIdentity>,
    @SerialName(SerialNames.LOTE_TYPE)
    val loteType: Rfc3986UniformResourceIdentifier,
    @SerialName(SerialNames.SCHEME_OPERATOR_NAME)
    val schemeOperatorName: SchemeOperatorName,
    @SerialName(SerialNames.SCHEME_TYPE_COMMUNITY_RULES)
    val schemeTypeCommunityRules: SchemeTypeCommunityRules? = null,
    @SerialName(SerialNames.SCHEME_TERRITORY)
    val schemeTerritory: EtsiCountryCode? = null,
    @SerialName(SerialNames.MIME_TYPE)
    val mimeType: Rfc6838MimeType? = null,
) {
    init {
        require(serviceDigitalIdentity.isNotEmpty()) {
            "Expected at least 1 ServiceDigitalIdentity."
        }
    }

    object SerialNames {
        const val LOTE_LOCATION = "LoTELocation"
        const val SERVICE_DIGITAL_IDENTITY = "ServiceDigitalIdentity"
        const val LOTE_TYPE = "LoTEType"
        const val SCHEME_OPERATOR_NAME = "SchemeOperatorName"
        const val SCHEME_TYPE_COMMUNITY_RULES = "SchemeTypeCommunityRules"
        const val SCHEME_TERRITORY = "SchemeTerritory"
        const val MIME_TYPE = "MimeType"
    }
}
