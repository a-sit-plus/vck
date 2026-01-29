package at.asitplus.dcapi.issuance

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * Parent for DC API issuance requests
 */
@Serializable
data class DigitalCredentialCreationOptions(
    @SerialName("requests")
    val requests: List<DigitalCredentialCreateRequest>,
)
