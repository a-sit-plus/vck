package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum

data class DCQLIsoMdocCredential(
    override val claimStructure: DCQLCredentialClaimStructure.IsoMdocStructure,
    val documentType: String,
    override val satisfiesCryptographicHolderBinding: Boolean,
    override val authorityKeyIdentifiers: Collection<DCQLAuthorityKeyIdentifier>,
) : DCQLCredential {
    override val format: CredentialFormatEnum
        get() = CredentialFormatEnum.MSO_MDOC

    override val isSelectivelyDisclosable: Boolean
        get() = true
}