package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 *  6.1. Credential Query
 *
 * A Credential Query is an object representing a request for a presentation of one Credential.
 * Note that multiple Credential Queries in a request MAY request a presentation of the same Credential.
 */
@Serializable
data class DCQLSdJwtCredentialQuery(
    @SerialName(DCQLCredentialQuery.SerialNames.ID)
    override val id: DCQLCredentialQueryIdentifier,
    @SerialName(DCQLCredentialQuery.SerialNames.FORMAT)
    override val format: CredentialFormatEnum,
    @SerialName(DCQLCredentialQuery.SerialNames.META)
    override val meta: DCQLSdJwtCredentialMetadataAndValidityConstraints,
    @SerialName(DCQLCredentialQuery.SerialNames.CLAIMS)
    override val claims: DCQLClaimsQueryList<DCQLJsonClaimsQuery>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.CLAIM_SETS)
    override val claimSets: NonEmptyList<List<DCQLClaimsQueryIdentifier>>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.MULTIPLE)
    override val multiple: Boolean? = false,
    @SerialName(DCQLCredentialQuery.SerialNames.TRUSTED_AUTHORITIES)
    override val trustedAuthorities: NonEmptyList<DCQLTrustedAuthorityQueryEntry>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING)
    override val requireCryptographicHolderBinding: Boolean? = true,
) : DCQLCredentialQuery {
    init {
        validate()
    }

    override fun validate() {
        super.validate()

        if (format != CredentialFormatEnum.DC_SD_JWT) {
            throw IllegalArgumentException("Value has an invalid format identifier in this context.")
        }
    }
}