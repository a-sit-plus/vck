package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum

data class DCQLVcJwsCredential(
    override val claimStructure: DCQLCredentialClaimStructure.JsonBasedStructure,
    override val satisfiesCryptographicHolderBinding: Boolean,
    override val authorityKeyIdentifiers: Collection<DCQLAuthorityKeyIdentifier>,
    val types: List<String>,
) : DCQLCredential {
    override val format: CredentialFormatEnum
        get() = CredentialFormatEnum.JWT_VC

    override val isSelectivelyDisclosable: Boolean
        get() = false
}