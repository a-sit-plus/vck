package at.asitplus.dcapi.issuance

import io.github.aakira.napier.Napier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * Contained in [CredentialCreationOptions]
 */
@Serializable
data class DigitalCredentialCreationOptions(
    @SerialName("requests")
    val requests: List<DigitalCredentialCreateRequest>,
)