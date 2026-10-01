package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC

data class IsoMdocFallbackCredentialScheme(
    override val isoDocType: String,
    override val isoNamespace: String = isoDocType,
) : IsoMdocCredentialScheme {
    override val supportedRepresentations: Collection<CredentialRepresentation> = listOf(ISO_MDOC)
}