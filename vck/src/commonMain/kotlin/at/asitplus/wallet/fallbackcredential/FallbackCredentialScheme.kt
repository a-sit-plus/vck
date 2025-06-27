package at.asitplus.wallet.fallbackcredential

import at.asitplus.wallet.lib.data.ConstantIndex

data class FallbackCredentialScheme(override val vcType: String? = null, override val isoDocType: String? = null, override val sdJwtType: String? = null) : ConstantIndex.CredentialScheme {
    companion object : ConstantIndex.CredentialScheme {
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown.json"
    }

    override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown.json"
    override val isoNamespace: String? = null
    override val supportedRepresentations: Collection<ConstantIndex.CredentialRepresentation> = listOf(
        ConstantIndex.CredentialRepresentation.SD_JWT,
        ConstantIndex.CredentialRepresentation.PLAIN_JWT, ConstantIndex.CredentialRepresentation.ISO_MDOC
    )
    override val claimNames: Collection<String> = listOf()
}