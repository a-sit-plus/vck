package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT

data class SdJwtFallbackCredentialScheme(
    override val sdJwtType: String,
) : SdJwtCredentialScheme {
    companion object : CredentialScheme {
        @Deprecated("Use other identifiers instead, e.g. `vcType` or `sdJwtType` or `isoDocType`")
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown_sd.json"
    }

    @Deprecated("Use other identifiers instead, e.g. `vcType` or `sdJwtType` or `isoDocType`")
    override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown_sd.json"
    override val supportedRepresentations: Collection<CredentialRepresentation> = listOf(SD_JWT)
}