package at.asitplus.etsi.relyingParty

import at.asitplus.data.NonEmptyList
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C credential metadata block.
 */
@Serializable
data class WrpCredentialMeta(
    @SerialName("doctype_value")
    val doctypeValue: String? = null,

    @SerialName("vct_values")
    val vctValues: NonEmptyList<String>? = null
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
        @SerialName("doctype_value") val doctypeValue: String,
    ) : WrpCredentialMetaDomain

    data class WrpVctTypeDomain(
        @SerialName("vct_values") val vctValues: NonEmptyList<String>
    ) : WrpCredentialMetaDomain
}
