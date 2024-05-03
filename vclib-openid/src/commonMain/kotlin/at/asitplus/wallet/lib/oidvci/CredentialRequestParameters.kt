package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialRequestParameters(
    /**
     * OID4VCI: REQUIRED when the `credential_identifiers` parameter was not returned from the Token Response.
     * It MUST NOT be used otherwise. It is a String that determines the format of the Credential to be issued,
     * which may determine the type and any other information related to the Credential to be issued.
     * Credential Format Profiles consist of the Credential format specific parameters that are defined in Appendix A.
     * When this parameter is used, the [credentialIdentifier] Credential Request parameter MUST NOT be present.
     * REQUIRED. Format of the Credential to be issued. This Credential format identifier determines further parameters
     * required to determine the type and (optionally) the content of the credential to be issued.
     */
    @SerialName("format")
    val format: CredentialFormatEnum? = null,

    /**
     * OID4VCI: REQUIRED when `credential_identifiers` parameter was returned from the Token Response.
     * It MUST NOT be used otherwise. It is a String that identifies a Credential that is being requested to be issued.
     * When this parameter is used, the [format] parameter and any other Credential format specific parameters such
     * as those defined in Appendix A MUST NOT be present.
     */
    @SerialName("credential_identifier")
    val credentialIdentifier: String? = null,

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
     * OID4VCI: OPTIONAL. Object containing the proof of possession of the cryptographic key material the issued
     * Credential would be bound to. The proof object is REQUIRED if the [SupportedCredentialFormat.supportedProofTypes]
     * parameter is non-empty and present in the [IssuerMetadata.supportedCredentialConfigurations] for the requested
     * Credential.
     */
    @SerialName("proof")
    val proof: CredentialRequestProof? = null,
)