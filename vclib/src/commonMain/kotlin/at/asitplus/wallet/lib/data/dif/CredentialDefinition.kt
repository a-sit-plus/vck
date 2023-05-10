package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Credential Manifest v1.0.0](https://identity.foundation/credential-manifest/#credential-manifest-3)
 */
@Serializable
data class CredentialDefinition(
    @SerialName("name")
    val name: String,
    @SerialName("schema")
    val schema: SchemaReference
)