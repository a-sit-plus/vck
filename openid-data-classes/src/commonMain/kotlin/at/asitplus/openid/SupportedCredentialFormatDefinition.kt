package at.asitplus.openid

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
    val types: Set<String>? = null,

)