package at.asitplus.wallet.lib.oidvci

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

    @SerialName("types")
    val types: Array<String> = arrayOf(),

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
        return proof == other.proof
    }

    override fun hashCode(): Int {
        var result = format.hashCode()
        result = 31 * result + types.contentHashCode()
        result = 31 * result + (proof?.hashCode() ?: 0)
        return result
    }
}