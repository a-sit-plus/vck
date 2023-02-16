package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Credential Manifest v1.0.0](https://identity.foundation/credential-manifest/#credential-manifest-3)
 */
@Serializable
data class CredentialManifest(
    @SerialName("issuer")
    val issuer: String,
    @SerialName("subject")
    val subject: String?,
    @SerialName("credential")
    val credential: CredentialDefinition,
)