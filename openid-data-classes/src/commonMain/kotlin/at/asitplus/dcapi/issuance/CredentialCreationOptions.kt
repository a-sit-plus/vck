package at.asitplus.dcapi.issuance

import at.asitplus.openid.CredentialOffer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Parent for DC API issuance requests
 */
@ConsistentCopyVisibility
@Serializable
data class CredentialCreationOptions private constructor(
    @SerialName("mediation")
    val mediation: String,
    @SerialName("digital")
    val digital: DigitalCredentialCreationOptions,
) {
    companion object {
        fun create(
            digital: DigitalCredentialCreationOptions,
        ) = CredentialCreationOptions(
            mediation = MEDIATION_REQUIRED,
            digital = digital
        )

        fun create(
            offer: CredentialOffer,
            protocol: IssuanceProtocolIdentifier = IssuanceProtocolIdentifier.OPENID4VCI_V1,
        ) = CredentialCreationOptions(
            mediation = MEDIATION_REQUIRED, digital = DigitalCredentialCreationOptions(
                listOf(
                    DigitalCredentialCreateRequest(protocol, offer)
                )
            )
        )

        private const val MEDIATION_REQUIRED = "required"

    }
}
