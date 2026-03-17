package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum

data class DCQLSdJwtCredential(
    override val claimStructure: DCQLCredentialClaimStructure.JsonBasedStructure,
    val type: String,
    override val satisfiesCryptographicHolderBinding: Boolean,
    override val authorityKeyIdentifiers: Collection<DCQLAuthorityKeyIdentifier>,
) : DCQLCredential {
    override val format: CredentialFormatEnum
        get() = CredentialFormatEnum.DC_SD_JWT

    override val isSelectivelyDisclosable: Boolean
        get() = true
}