package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C credential metadata block.
 */
@Serializable
data class WrpCredentialMeta(
    /** ISO mdoc document type identifying the credential (Annex C). */
    @SerialName("doctype_value")
    val doctypeValue: String? = null,

    /** SD-JWT VC type identifiers identifying the credentials (Annex C). */
    @SerialName("vct_values")
    val vctValues: List<String>? = null
) {
    fun toDomain() = when {
        doctypeValue != null -> WrpCredentialMetaDomain.WrpDocTypeDomain(doctypeValue)
        vctValues != null -> WrpCredentialMetaDomain.WrpVctTypeDomain(vctValues)
        else -> throw Throwable("WrpCredentialMetaDto empty")
    }
}

@Serializable
sealed interface WrpCredentialMetaDomain {
    data class WrpDocTypeDomain(
        /** ISO mdoc document type identifying the credential (Annex C). */
        @SerialName("doctype_value") val doctypeValue: String,
    ) : WrpCredentialMetaDomain

    data class WrpVctTypeDomain(
        /** SD-JWT VC type identifiers identifying the credentials (Annex C). */
        @SerialName("vct_values") val vctValues: List<String>
    ) : WrpCredentialMetaDomain
}
