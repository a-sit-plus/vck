package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DCQLIsoMdocCredentialQuery(
    @SerialName(DCQLCredentialQuery.SerialNames.ID)
    override val id: DCQLCredentialQueryIdentifier,
    @SerialName(DCQLCredentialQuery.SerialNames.META)
    override val meta: DCQLIsoMdocCredentialMetadataAndValidityConstraints,
    @SerialName(DCQLCredentialQuery.SerialNames.CLAIMS)
    override val claims: DCQLClaimsQueryList<DCQLIsoMdocClaimsQuery>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.CLAIM_SETS)
    override val claimSets: NonEmptyList<List<DCQLClaimsQueryIdentifier>>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.MULTIPLE)
    override val multiple: Boolean? = false,
    @SerialName(DCQLCredentialQuery.SerialNames.TRUSTED_AUTHORITIES)
    override val trustedAuthorities: NonEmptyList<DCQLTrustedAuthorityQueryEntry>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING)
    override val requireCryptographicHolderBinding: Boolean? = true,
    @SerialName(DCQLCredentialQuery.SerialNames.FORMAT)
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    override val format: CredentialFormatEnum = CREDENTIAL_FORMAT,
) : DCQLCredentialQuery {
    init {
        validate()
    }

    companion object {
        val CREDENTIAL_FORMAT = CredentialFormatEnum.MSO_MDOC
    }

    override fun validate() {
        super.validate()
        require(format == CREDENTIAL_FORMAT) {
            "Value has an invalid format identifier in this context."
        }
    }
}