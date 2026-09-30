package at.asitplus.csc.datamodel.requests

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model 1.0.0 section 9.2. */
@Serializable
data class CredentialDeletionRequest(
    /**
     * CSC Data Model 1.0.0 section 9.2: REQUIRED
     * Identifier of the credential to delete.
     */
    @SerialName("credentialID")
    val credentialId: String,
    /**
     * CSC Data Model 1.0.0 section 9.2: OPTIONAL
     * Whether deletion also revokes the credential.
     */
    @SerialName("revoke")
    val revoke: Boolean? = null,
    /**
     * CSC Data Model 1.0.0 section 9.2: CONDITIONAL
     * Required when [revoke] is `true`; MUST be ignored when [revoke] is absent or `false` (RFC 5280).
     */
    @SerialName("revocationReason")
    val revocationReason: Int? = null,
) {
    init {
        require(credentialId.isNotBlank()) { "credentialID must not be blank" }
        require(
            revoke != true || (revocationReason != null && revocationReason in 0..10 && revocationReason != 7)
        ) {
            "revocationReason must be present and valid when revoke is true"
        }
    }
}
