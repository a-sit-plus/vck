package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialRequestParameters(
    /**
     * OID4VCI:
     * REQUIRED. Format of the Credential to be issued. This Credential format identifier determines further parameters
     * required to determine the type and (optionally) the content of the credential to be issued.
     */
    @SerialName("format")
    val format: CredentialFormatEnum,

    /**
     * OID4VCI:
     * ISO mDL: N/A.
     * W3C Verifiable Credentials: REQUIRED.
     *
     * JSON array designating the types a certain credential type supports according to (VC_DATA),
     * Section 4.3.
     * e.g. `VerifiableCredential`, `UniversityDegreeCredential`.
     */
    @SerialName("types")
    val types: Array<String> = arrayOf(),

    /**
     * OID4VCI:
     * ISO mDL: REQUIRED.
     * W3C Verifiable Credentials: N/A.
     *
     * JSON string identifying the credential type.
     */
    @SerialName("doctype")
    val docType: String? = null,

    /**
     * OID4VCI:
     * ISO mDL: OPTIONAL.
     * W3C Verifiable Credentials: N/A.
     *
     * A JSON object containing a list of key value pairs,
     * where the key is a certain namespace as defined in [ISO.18013-5] (or any profile of it),
     * and the value is a JSON object. This object also contains a list of key value pairs,
     * where the key is a claim that is defined in the respective namespace and is offered in the Credential.
     */
    @SerialName("claims")
    val claims: Map<String, Map<String, RequestedCredentialClaimSpecification>>? = null,

    /**
     * OID4VCI:
     * OPTIONAL. JSON object containing proof of possession of the key material the issued Credential shall be bound to.
     * The specification envisions use of different types of proofs for different cryptographic schemes. The proof
     * object MUST contain a proof_type claim of type JSON string denoting the concrete proof type. This type determines
     * the further claims in the proof object and its respective processing rules.
     */
    @SerialName("proof")
    val proof: CredentialRequestProof? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CredentialRequestParameters

        if (format != other.format) return false
        if (!types.contentEquals(other.types)) return false
        if (docType != other.docType) return false
        if (claims != other.claims) return false
        return proof == other.proof
    }

    override fun hashCode(): Int {
        var result = format.hashCode()
        result = 31 * result + types.contentHashCode()
        result = 31 * result + (docType?.hashCode() ?: 0)
        result = 31 * result + (claims?.hashCode() ?: 0)
        result = 31 * result + (proof?.hashCode() ?: 0)
        return result
    }
}