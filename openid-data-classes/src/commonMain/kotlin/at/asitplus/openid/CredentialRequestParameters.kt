package at.asitplus.openid

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

@Serializable
data class CredentialRequestParameters(
    /**
     * OID4VCI: REQUIRED when an [AuthorizationDetails.OpenIdAuthorizationDetails] was returned from the
     * [TokenResponseParameters]. It MUST NOT be used otherwise. A string that identifies a Credential Dataset that is
     * requested for issuance. When this parameter is used, the [format] parameter and any other Credential format
     * specific parameters such as those defined in Appendix A MUST NOT be present
     */
    @SerialName("credential_identifier")
    // TODO Update
    val credentialIdentifier: String? = null,

    /**
     * OID4VCI: REQUIRED if an [AuthorizationDetails.OpenIdAuthorizationDetails] was not returned from the
     * [TokenResponseParameters] (e.g. when the credential was requested using a [AuthenticationRequestParameters.scope]
     * or a pre-authorisation code was used that did not return an [AuthorizationDetails.OpenIdAuthorizationDetails]).
     * It MUST NOT be used otherwise. A string that determines the format of the Credential to be issued, which may
     * determine the type and any other information related to the Credential to be issued. Credential Format Profiles
     * consist of the Credential format specific parameters that are defined in Appendix A. When this parameter is used,
     * the [credentialIdentifier] parameter MUST NOT be present.
     */
    @SerialName("format")
    val format: CredentialFormatEnum? = null,

    /**
     * OID4VCI:  OPTIONAL. Object containing information for encrypting the Credential Response. If this request element
     * is not present, the corresponding credential response returned is not encrypted.
     */
    @SerialName("credential_response_encryption")
    val credentialResponseEncryption: SupportedAlgorithmsContainer? = null,

    /**
     * OID4VCI: ISO mDL: OPTIONAL. This claim contains the type value the Wallet requests authorization for at the
     * Credential Issuer. It MUST only be present if the [format] claim is present. It MUST not be present otherwise.
     */
    @SerialName("doctype")
    val docType: String? = null,

    /**
     * OID4VCI: ISO mDL: OPTIONAL. Object as defined in Appendix A.3.2 excluding the `display` and `value_type`
     * parameters. The `mandatory` parameter here is used by the Wallet to indicate to the Issuer that it only accepts
     * Credential(s) issued with those claim(s).
     */
    @SerialName("claims")
    // TODO Verify format for ISO-MDOC and SD-JWT
    val claims: Map<String, Map<String, RequestedCredentialClaimSpecification>>? = null,

    /**
     * OID4VCI: W3C VC: OPTIONAL. Object containing a detailed description of the Credential consisting of the
     * following parameters. see [SupportedCredentialFormatDefinition].
     */
    @SerialName("credential_definition")
    val credentialDefinition: SupportedCredentialFormatDefinition? = null,

    /**
     * OID4VCI: IETF SD-JWT VC: REQUIRED. String as defined in Appendix A.3.2. This claim contains the type values
     * the Wallet requests authorization for at the Credential Issuer.
     * It MUST only be present if the [format] claim is present. It MUST not be present otherwise.
     */
    @SerialName("vct")
    val sdJwtVcType: String? = null,

    /**
     * OID4VCI: OPTIONAL. Object providing a single proof of possession of the cryptographic key material to which the
     * issued Credential instance will be bound to. [proof] parameter MUST NOT be present if [proofs] parameter is used.
     */
    @SerialName("proof")
    val proof: CredentialRequestProof? = null,

    /**
     * OID4VCI: OPTIONAL. Object providing one or more proof of possessions of the cryptographic key material to which
     * the issued Credential instances will be bound to. The [proofs] parameter MUST NOT be present if [proof] parameter
     * is used. [proofs] object contains exactly one parameter named as the proof type in Section 7.2.1, the value set
     * for this parameter is an array containing parameters as defined by the corresponding proof type.
     */
    @SerialName("proofs")
    val proofs: CredentialRequestProofContainer? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<CredentialRequestParameters> =
            runCatching { jsonSerializer.decodeFromString<CredentialRequestParameters>(input) }.wrap()
    }

}
