package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C credential descriptor.
 */
@Serializable
data class WrpCredential(
    /** Attestation format identifier (clause B.2.9). */
    @SerialName("format")
    val format: String,

    /** Additional metadata specific to the credential format (clause B.2.9). */
    @SerialName("meta")
    val meta: WrpCredentialMeta,

    /**
     * Attributes declared for requesting or providing; absence declares no specific requested attributes
     * (Tables 8 and 9; claim `[0..*]`, clause B.2.9).
     */
    @SerialName("claim")
    val claim: List<WrpClaim>? = null
) {
    init {
        require(claim?.isNotEmpty() != false) { "claim must not be empty" } // B.2.9 refers to OpenID4VP 1.0, 6.1
    }
}
