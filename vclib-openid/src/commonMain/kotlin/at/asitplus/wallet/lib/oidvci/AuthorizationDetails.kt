package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * To be contained in an array sent in parameter `authorization_details` from the Wallet to the Issuer
 */
@Serializable
data class AuthorizationDetails(
    /**
     * Must be `openid_credential`
     */
    @SerialName("type")
    val type: String,

    @SerialName("format")
    val format: CredentialFormatEnum,

    /**
     * OIDVCI: Required for ISO mDL: JSON string identifying the credential type.
     */
    @SerialName("doctype")
    val docType: String? = null,

    /**
     * OIDVCI: Optional for ISO mDL: A JSON object containing a list of key value pairs, where the key is a certain
     * namespace as defined in ISO.18013-5 (or any profile of it), and the value is a JSON object. This object also
     * contains a list of key value pairs, where the key is a claim that is defined in the respective namespace and is
     * offered in the Credential.
     */
    @SerialName("claims")
    val claims: Map<String, Map<String, RequestedCredentialClaimSpecification>>? = null,

    /**
     * e.g. `VerifiableCredential`, `UniversityDegreeCredential`
     */
    @SerialName("types")
    val types: Array<String>,

    /**
     * Must contain the `authorization_server` entry from the Issuer's metadata
     */
    @SerialName("locations")
    val locations: Array<String>? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as AuthorizationDetails

        if (type != other.type) return false
        if (format != other.format) return false
        if (docType != other.docType) return false
        if (claims != other.claims) return false
        if (!types.contentEquals(other.types)) return false
        if (locations != null) {
            if (other.locations == null) return false
            if (!locations.contentEquals(other.locations)) return false
        } else if (other.locations != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + format.hashCode()
        result = 31 * result + (docType?.hashCode() ?: 0)
        result = 31 * result + (claims?.hashCode() ?: 0)
        result = 31 * result + types.contentHashCode()
        result = 31 * result + (locations?.contentHashCode() ?: 0)
        return result
    }
}