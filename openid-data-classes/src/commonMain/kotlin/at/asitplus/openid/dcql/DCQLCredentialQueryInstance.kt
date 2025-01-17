package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DCQLCredentialQueryInstance(
    @SerialName(DCQLCredentialQuery.SerialNames.ID)
    override val id: DCQLCredentialQueryIdentifier,
    @SerialName(DCQLCredentialQuery.SerialNames.FORMAT)
    override val format: CredentialFormatEnum,
    @SerialName(DCQLCredentialQuery.SerialNames.META)
    override val meta: DCQLCredentialMetadataAndValidityConstraints? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.CLAIMS)
    override val claims: List<DCQLClaimsQuery>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.CLAIM_SETS)
    override val claimSets: List<List<DCQLClaimsQueryIdentifier>>? = null,
) : DCQLCredentialQuery {
    init {
        DCQLCredentialQuery.validate(this)
    }
}