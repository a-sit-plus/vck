package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT

data class VcFallbackCredentialScheme(
    override val vcType: String,
) : VcJwtCredentialScheme {
    override val supportedRepresentations: Collection<CredentialRepresentation> = listOf(PLAIN_JWT)
}