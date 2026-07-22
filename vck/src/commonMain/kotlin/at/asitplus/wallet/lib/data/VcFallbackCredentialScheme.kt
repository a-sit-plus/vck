package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT

data class VcFallbackCredentialScheme(
    override val vcType: String,
) : VcJwtCredentialScheme {
    companion object : CredentialScheme {
        @Deprecated("Use other identifiers instead, e.g. `vcType` or `sdJwtType` or `isoDocType`")
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown_vc.json"
    }

    @Deprecated("Use other identifiers instead, e.g. `vcType` or `sdJwtType` or `isoDocType`")
    override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown_vc.json"
    override val supportedRepresentations: Collection<CredentialRepresentation> = listOf(PLAIN_JWT)
}