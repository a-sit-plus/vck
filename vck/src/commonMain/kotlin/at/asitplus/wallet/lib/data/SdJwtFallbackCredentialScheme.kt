package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT

data class SdJwtFallbackCredentialScheme(
    override val sdJwtType: String,
) : SdJwtCredentialScheme {
    override val supportedRepresentations: Collection<CredentialRepresentation> = listOf(SD_JWT)
}