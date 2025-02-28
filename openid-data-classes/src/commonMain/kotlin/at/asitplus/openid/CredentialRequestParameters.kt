package at.asitplus.openid

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

@Serializable
data class CredentialRequestParameters(
    /**
     * OID4VCI: REQUIRED when an Authorization Details of type [OpenIdAuthorizationDetails] was returned from the Token
     * Response. It MUST NOT be used otherwise. A string that identifies a Credential Dataset that is requested for
     * issuance. When this parameter is used, the [credentialConfigurationId] MUST NOT be present.
     */
    @SerialName("credential_identifier")
    val credentialIdentifier: String? = null,

    /**
     * OID4VCI: REQUIRED if a `credential_identifiers` parameter was not returned from the Token Response as part of
     * the `authorization_details` parameter (see [OpenIdAuthorizationDetails.credentialIdentifiers]). It MUST NOT be
     * used otherwise. String that uniquely identifies one of the keys in the name/value pairs stored in the
     * [IssuerMetadata.supportedCredentialConfigurations].
     * The corresponding object in the [IssuerMetadata.supportedCredentialConfigurations] MUST contain one of the
     * value(s) used in the [AuthenticationRequestParameters.scope].
     * When this parameter is used, the [credentialIdentifier] MUST NOT be present.
     */
    @SerialName("credential_configuration_id")
    val credentialConfigurationId: String? = null,

    @SerialName("format")
    @Deprecated("Removed in OID4VCI draft 15")
    val format: CredentialFormatEnum? = null,

    /**
     * OID4VCI:  OPTIONAL. Object containing information for encrypting the Credential Response. If this request element
     * is not present, the corresponding credential response returned is not encrypted.
     */
    @SerialName("credential_response_encryption")
    val credentialResponseEncryption: SupportedAlgorithmsContainer? = null, // TODO other type

    @SerialName("doctype")
    @Deprecated("Removed in OID4VCI draft 15")
    val docType: String? = null,

    @SerialName("claims")
    @Deprecated("Removed in OID4VCI draft 15")
    val claims: Map<String, Map<String, RequestedCredentialClaimSpecification>>? = null,

    /**
     * OID4VCI: W3C VC: OPTIONAL. Object containing a detailed description of the Credential consisting of the
     * following parameters. see [SupportedCredentialFormatDefinition].
     */
    @SerialName("credential_definition")
    val credentialDefinition: SupportedCredentialFormatDefinition? = null,

    @SerialName("vct")
    @Deprecated("Removed in OID4VCI draft 15")
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

    fun serialize() = odcJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<CredentialRequestParameters> =
            runCatching { odcJsonSerializer.decodeFromString<CredentialRequestParameters>(input) }.wrap()
    }

}
