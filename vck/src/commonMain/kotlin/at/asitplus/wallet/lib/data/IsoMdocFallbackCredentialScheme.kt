package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC

data class IsoMdocFallbackCredentialScheme(
    override val isoDocType: String,
    override val isoNamespace: String = isoDocType,
) : IsoMdocCredentialScheme {
    companion object : CredentialScheme {
        @Deprecated("Use other identifiers instead, e.g. `vcType` or `sdJwtType` or `isoDocType`")
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown_iso.json"
    }

    @Deprecated("Use other identifiers instead, e.g. `vcType` or `sdJwtType` or `isoDocType`")
    override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown_iso.json"
    override val supportedRepresentations: Collection<CredentialRepresentation> = listOf(ISO_MDOC)
}