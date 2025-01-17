package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DCQLIsoMdocCredentialQuery(
    @SerialName(DCQLCredentialQuery.SerialNames.ID)
    override val id: DCQLCredentialQueryIdentifier,
    @SerialName(DCQLCredentialQuery.SerialNames.FORMAT)
    override val format: CredentialFormatEnum,
    @SerialName(DCQLCredentialQuery.SerialNames.META)
    override val meta: DCQLIsoMdocCredentialMetadataAndValidityConstraints? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.CLAIMS)
    override val claims: List<DCQLIsoMdocClaimsQuery>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.CLAIM_SETS)
    override val claimSets: List<List<DCQLClaimsQueryIdentifier>>? = null,
) : DCQLCredentialQuery {
    init {
        validate(this)
    }

    companion object {
        fun validate(query: DCQLIsoMdocCredentialQuery) = query.run {
            DCQLCredentialQuery.validate(this)
            if (format != CredentialFormatEnum.MSO_MDOC) {
                throw IllegalArgumentException("Value has an invalid format identifier in this context.")
            }
        }
    }
}