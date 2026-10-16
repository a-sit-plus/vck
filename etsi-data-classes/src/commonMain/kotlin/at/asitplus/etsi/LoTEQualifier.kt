package at.asitplus.etsi

import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Qualifiers of a referenced list of trusted entities (TS 119 602, Annex A.1). */
@Serializable
data class LoTEQualifier(
    /** Type URI of the referenced list (TS 119 602, 6.3.13). */
    @SerialName(SerialNames.LOTE_TYPE)
    val loteType: Rfc3986UniformResourceIdentifier,
    /** Name of the scheme operator responsible for the referenced list (TS 119 602, 6.3.13). */
    @SerialName(SerialNames.SCHEME_OPERATOR_NAME)
    val schemeOperatorName: SchemeOperatorName,
    /** Pointers to the type, community and rules of the referenced list scheme (TS 119 602, 6.3.13). */
    @SerialName(SerialNames.SCHEME_TYPE_COMMUNITY_RULES)
    val schemeTypeCommunityRules: SchemeTypeCommunityRules? = null,
    /** Territory of the referenced list scheme (TS 119 602, 6.3.13). */
    @SerialName(SerialNames.SCHEME_TERRITORY)
    val schemeTerritory: EtsiCountryCode? = null,
    /** Media type of the referenced machine-processable list (TS 119 602, 6.3.13). */
    @SerialName(SerialNames.MIME_TYPE)
    val mimeType: Rfc6838MimeType,
) {
    object SerialNames {
        /** Wire member name `LoTEType`. */
        const val LOTE_TYPE = "LoTEType"
        /** Wire member name `SchemeOperatorName`. */
        const val SCHEME_OPERATOR_NAME = "SchemeOperatorName"
        /** Wire member name `SchemeTypeCommunityRules`. */
        const val SCHEME_TYPE_COMMUNITY_RULES = "SchemeTypeCommunityRules"
        /** Wire member name `SchemeTerritory`. */
        const val SCHEME_TERRITORY = "SchemeTerritory"
        /** Wire member name `MimeType`. */
        const val MIME_TYPE = "MimeType"
    }
}
