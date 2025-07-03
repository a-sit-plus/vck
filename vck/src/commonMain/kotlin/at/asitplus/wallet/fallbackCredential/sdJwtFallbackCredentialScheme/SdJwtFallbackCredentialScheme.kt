package at.asitplus.wallet.fallbackCredential.sdJwtFallbackCredentialScheme

import at.asitplus.wallet.lib.data.ConstantIndex

data class SdJwtFallbackCredentialScheme(override val sdJwtType: String) : ConstantIndex.CredentialScheme {
    companion object : ConstantIndex.CredentialScheme {
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown_sd.json"
    }

    override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown_sd.json"
    override val isoNamespace: String? = null
    override val supportedRepresentations: Collection<ConstantIndex.CredentialRepresentation> = listOf(ConstantIndex.CredentialRepresentation.SD_JWT)
    override val claimNames: Collection<String> = listOf()
}