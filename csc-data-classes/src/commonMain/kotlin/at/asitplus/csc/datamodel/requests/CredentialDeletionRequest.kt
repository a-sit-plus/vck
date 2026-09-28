package at.asitplus.csc.datamodel.requests

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model 1.0.0 section 9.2. */
@Serializable
data class CredentialDeletionRequest(
    @SerialName("credentialID")
    val credentialId: String,
    @SerialName("revoke")
    val revoke: Boolean? = null,
    @SerialName("revocationReason")
    val revocationReason: Int? = null,
) {
    init {
        require(credentialId.isNotBlank()) { "credentialID must not be blank" }
        require(revoke != true || revocationReason != null) {
            "revocationReason is required when revoke is true"
        }
        require(revocationReason == null || revocationReason in 0..10 && revocationReason != 7) {
            "revocationReason must be an RFC 5280 reason code from 0 to 10 other than 7"
        }
    }
}