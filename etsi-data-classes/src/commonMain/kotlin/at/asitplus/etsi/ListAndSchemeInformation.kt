package at.asitplus.etsi

import at.asitplus.rfc.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class ListAndSchemeInformation(
    @SerialName(SerialNames.LOTE_VERSION_IDENTIFIER)
    val loTEVersionIdentifier: Int,
    @SerialName(SerialNames.LOTE_SEQUENCE_NUMBER)
    val loTESequenceNumber: Int,
    @SerialName(SerialNames.LIST_ISSUE_DATE_TIME)
    @Serializable(with = EtsiInstantSerializer::class)
    val listIssueDateTime: Instant,
    @SerialName(SerialNames.NEXT_UPDATE)
    @Serializable(with = EtsiInstantSerializer::class)
    val nextUpdate: Instant,
    @SerialName(SerialNames.SCHEME_OPERATOR_NAME)
    val schemeOperatorName: SchemeOperatorName,
    @SerialName(SerialNames.LOTE_TYPE)
    val loteType: Rfc3986UniformResourceIdentifier? = null,
    @SerialName(SerialNames.SCHEME_OPERATOR_ADDRESS)
    val schemeOperatorAddress: SchemeOperatorAddress? = null,
    @SerialName(SerialNames.SCHEME_NAME)
    val schemeName: SchemeName? = null,
    @SerialName(SerialNames.SCHEME_INFORMATION_URI)
    val schemeInformationURI: SchemeInformationURI? = null,
    @SerialName(SerialNames.SCHEME_DETERMINATION_APPROACH)
    val statusDeterminationApproach: Rfc3986UniformResourceIdentifier? = null,
    @SerialName(SerialNames.SCHEME_TYPE_COMMUNItY_RULES)
    val schemeTypeCommunityRules: SchemeTypeCommunityRules? = null,
    @SerialName(SerialNames.SCHEME_TERRITORY)
    val schemeTerritory: EtsiCountryCode? = null,
    @SerialName(SerialNames.POLICY_OR_LEGAL_NOTICE)
    val policyOrLegalNotice: PolicyOrLegalNotice? = null,
    @SerialName(SerialNames.HISTORICAL_INFORMATION_PERIOD)
    val historicalInformationPeriod: Int? = null,
    @SerialName(SerialNames.POINTER_TO_OTHER_LOTE)
    val pointerToOtherLoTE: PointersToOtherLoTE? = null,
    @SerialName(SerialNames.DISTRIBUTION_POINTS)
    val distributionPoints: List<Rfc3986UniformResourceIdentifier>? = null,
    @SerialName(SerialNames.SCHEME_EXTENSIONS)
    val schemeExtensions: SchemeExtensions? = null,
) {
    object SerialNames {
        const val LOTE_VERSION_IDENTIFIER = "LoTEVersionIdentifier"
        const val LOTE_SEQUENCE_NUMBER = "LoTESequenceNumber"
        const val LIST_ISSUE_DATE_TIME = "ListIssueDateTime"
        const val NEXT_UPDATE = "NextUpdate"
        const val LOTE_TYPE = "LoTEType"
        const val DISTRIBUTION_POINTS = "DistributionPoints"
        const val SCHEME_OPERATOR_NAME = "SchemeOperatorName"
        const val SCHEME_OPERATOR_ADDRESS = "SchemeOperatorAddress"
        const val SCHEME_NAME = "SchemeName"
        const val SCHEME_INFORMATION_URI = "SchemeInformationURI"
        const val SCHEME_DETERMINATION_APPROACH = "StatusDeterminationApproach"
        const val SCHEME_TYPE_COMMUNItY_RULES = "SchemeTypeCommunityRules"
        const val SCHEME_TERRITORY = "SchemeTerritory"
        const val POLICY_OR_LEGAL_NOTICE = "PolicyOrLegalNotice"
        const val HISTORICAL_INFORMATION_PERIOD = "HistoricalInformationPeriod"
        const val POINTER_TO_OTHER_LOTE = "PointersToOtherLoTE"
        const val SCHEME_EXTENSIONS = "SchemeExtensions"
    }
}