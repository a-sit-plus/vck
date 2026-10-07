package at.asitplus.etsi

import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class ListAndSchemeInformation(
    /** Version of the LoTE format for the applicable syntax binding (TS 119 602, 6.3.1). */
    @SerialName(SerialNames.LOTE_VERSION_IDENTIFIER)
    val loTEVersionIdentifier: Int,
    /** Release number, starting at 1 and increasing with each subsequent issue (TS 119 602, 6.3.2). */
    @SerialName(SerialNames.LOTE_SEQUENCE_NUMBER)
    val loTESequenceNumber: Int,
    /** UTC date and time at which the list was issued (TS 119 602, 6.3.14). */
    @SerialName(SerialNames.LIST_ISSUE_DATE_TIME)
    @Serializable(with = EtsiInstantSerializer::class)
    val listIssueDateTime: Instant,
    /** Latest date and time for an updated list, or null for a closed list (TS 119 602, 6.3.15). */
    @SerialName(SerialNames.NEXT_UPDATE)
    @Serializable(with = EtsiInstantSerializer::class)
    val nextUpdate: Instant?,
    /** Formal name of the entity establishing, publishing, signing and maintaining the list (TS 119 602, 6.3.4). */
    @SerialName(SerialNames.SCHEME_OPERATOR_NAME)
    val schemeOperatorName: SchemeOperatorName,
    /** URI identifying the type of list and its applicable interpretation (TS 119 602, 6.3.3). */
    @SerialName(SerialNames.LOTE_TYPE)
    val loteType: Rfc3986UniformResourceIdentifier? = null,
    /** Postal and electronic contact addresses of the scheme operator (TS 119 602, 6.3.5). */
    @SerialName(SerialNames.SCHEME_OPERATOR_ADDRESS)
    val schemeOperatorAddress: SchemeOperatorAddress? = null,
    /** Localized name under which the scheme operates (TS 119 602, 6.3.6). */
    @SerialName(SerialNames.SCHEME_NAME)
    val schemeName: SchemeName? = null,
    /** Localized pointers to scheme-specific information (TS 119 602, 6.3.7). */
    @SerialName(SerialNames.SCHEME_INFORMATION_URI)
    val schemeInformationURI: SchemeInformationURI? = null,
    /** URI identifying the approach used to determine service status (TS 119 602, 6.3.8). */
    @SerialName(SerialNames.SCHEME_DETERMINATION_APPROACH)
    val statusDeterminationApproach: Rfc3986UniformResourceIdentifier? = null,
    /**
     * Pointers to the scheme type, community and rules for approving and assessing listed services (TS 119 602,
     * 6.3.9).
     */
    @SerialName(SerialNames.SCHEME_TYPE_COMMUNItY_RULES)
    val schemeTypeCommunityRules: SchemeTypeCommunityRules? = null,
    /** Country or territory in which the scheme is established and applies (TS 119 602, 6.3.10). */
    @SerialName(SerialNames.SCHEME_TERRITORY)
    val schemeTerritory: EtsiCountryCode? = null,
    /** Scheme policy or legal notices governing the list and its publication (TS 119 602, 6.3.11). */
    @SerialName(SerialNames.POLICY_OR_LEGAL_NOTICE)
    val policyOrLegalNotice: PolicyOrLegalNotice? = null,
    /** History retention period; 65535 means indefinite retention, absence means no history (TS 119 602, 6.3.12). */
    @SerialName(SerialNames.HISTORICAL_INFORMATION_PERIOD)
    val historicalInformationPeriod: Int? = null,
    /** References to relevant lists of trusted entities or lists of such lists (TS 119 602, 6.3.13). */
    @SerialName(SerialNames.POINTER_TO_OTHER_LOTE)
    val pointerToOtherLoTE: PointersToOtherLoTE? = null,
    /** Locations where the current list and its updates are published (TS 119 602, 6.3.16). */
    @SerialName(SerialNames.DISTRIBUTION_POINTS)
    val distributionPoints: List<Rfc3986UniformResourceIdentifier>? = null,
    /** Additional scheme-specific information without changing the format version (TS 119 602, 6.3.17). */
    @SerialName(SerialNames.SCHEME_EXTENSIONS)
    val schemeExtensions: SchemeExtensions? = null,
) {
    object SerialNames {
        /** Wire member name `LoTEVersionIdentifier`. */
        const val LOTE_VERSION_IDENTIFIER = "LoTEVersionIdentifier"
        /** Wire member name `LoTESequenceNumber`. */
        const val LOTE_SEQUENCE_NUMBER = "LoTESequenceNumber"
        /** Wire member name `ListIssueDateTime`. */
        const val LIST_ISSUE_DATE_TIME = "ListIssueDateTime"
        /** Wire member name `NextUpdate`. */
        const val NEXT_UPDATE = "NextUpdate"
        /** Wire member name `LoTEType`. */
        const val LOTE_TYPE = "LoTEType"
        /** Wire member name `DistributionPoints`. */
        const val DISTRIBUTION_POINTS = "DistributionPoints"
        /** Wire member name `SchemeOperatorName`. */
        const val SCHEME_OPERATOR_NAME = "SchemeOperatorName"
        /** Wire member name `SchemeOperatorAddress`. */
        const val SCHEME_OPERATOR_ADDRESS = "SchemeOperatorAddress"
        /** Wire member name `SchemeName`. */
        const val SCHEME_NAME = "SchemeName"
        /** Wire member name `SchemeInformationURI`. */
        const val SCHEME_INFORMATION_URI = "SchemeInformationURI"
        /** Wire member name `StatusDeterminationApproach`. */
        const val SCHEME_DETERMINATION_APPROACH = "StatusDeterminationApproach"
        /** Wire member name `SchemeTypeCommunityRules`. */
        const val SCHEME_TYPE_COMMUNItY_RULES = "SchemeTypeCommunityRules"
        /** Wire member name `SchemeTerritory`. */
        const val SCHEME_TERRITORY = "SchemeTerritory"
        /** Wire member name `PolicyOrLegalNotice`. */
        const val POLICY_OR_LEGAL_NOTICE = "PolicyOrLegalNotice"
        /** Wire member name `HistoricalInformationPeriod`. */
        const val HISTORICAL_INFORMATION_PERIOD = "HistoricalInformationPeriod"
        /** Wire member name `PointersToOtherLoTE`. */
        const val POINTER_TO_OTHER_LOTE = "PointersToOtherLoTE"
        /** Wire member name `SchemeExtensions`. */
        const val SCHEME_EXTENSIONS = "SchemeExtensions"
    }
}