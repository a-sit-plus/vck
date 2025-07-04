package at.asitplus.wallet.fallbackCredential.isoMdocFallbackCredentialScheme

import at.asitplus.wallet.lib.data.ConstantIndex

data class IsoMdocFallbackCredentialScheme(override val isoDocType: String, override val isoNamespace: String = isoDocType) : ConstantIndex.CredentialScheme {
    companion object : ConstantIndex.CredentialScheme {
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown_iso.json"
    }

    override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown_iso.json"
    override val supportedRepresentations: Collection<ConstantIndex.CredentialRepresentation> = listOf(ConstantIndex.CredentialRepresentation.ISO_MDOC)
    override val claimNames: Collection<String> = listOf()
}