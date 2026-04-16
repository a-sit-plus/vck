package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum

sealed interface DCQLCredential {
    val claimStructure: DCQLCredentialClaimStructure
    val satisfiesCryptographicHolderBinding: Boolean
    val authorityKeyIdentifiers: Collection<DCQLAuthorityKeyIdentifier>
    val format: CredentialFormatEnum
    val isSelectivelyDisclosable: Boolean
}