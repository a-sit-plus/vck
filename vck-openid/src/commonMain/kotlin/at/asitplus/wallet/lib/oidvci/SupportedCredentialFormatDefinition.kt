package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VCI: W3C VC:  REQUIRED. Object containing the detailed description of the Credential type.
 * It consists of at least the following two parameters: `type, `credentialSubject`.
 */
@Serializable
data class SupportedCredentialFormatDefinition(

    /**
     * OID4VCI: W3C VC: REQUIRED. JSON array designating the types a certain credential type supports
     * according to (VC_DATA), Section 4.3, e.g. `VerifiableCredential`, `UniversityDegreeCredential`
     */
    @SerialName("type")
    val types: Collection<String>? = null,

    /**
     * OID4VCI:
     * W3C VC: OPTIONAL. Object containing a list of name/value pairs, where each name identifies
     * a claim offered in the Credential. The value can be another such object (nested data structures), or an array
     * of such objects
     */
    @SerialName("credentialSubject")
    val credentialSubject: Map<String, CredentialSubjectMetadataSingle>? = null,

    // TODO is present in EUDIW issuer ... but is this really valid?
    @SerialName("claims")
    val claims: Map<String, RequestedCredentialClaimSpecification>? = null,
)