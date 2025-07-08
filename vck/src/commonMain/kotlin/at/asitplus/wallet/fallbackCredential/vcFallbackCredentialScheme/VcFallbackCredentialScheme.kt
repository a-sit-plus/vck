package at.asitplus.wallet.fallbackCredential.vcFallbackCredentialScheme

import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT

data class VcFallbackCredentialScheme(
    override val vcType: String,
) : ConstantIndex.CredentialScheme {
    companion object : ConstantIndex.CredentialScheme {
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown_vc.json"
    }

    override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown_vc.json"
    override val supportedRepresentations: Collection<CredentialRepresentation> = listOf(PLAIN_JWT)
}