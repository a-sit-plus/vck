package at.asitplus.openid

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement

@Serializable
data class CredentialRequestParameters(
    /**
     * OID4VCI: REQUIRED when an Authorization Details of type `openid_credential` was returned from the Token Response
     * (see [TokenResponseParameters.authorizationDetails]).
     * It MUST NOT be used otherwise. A string that identifies a Credential Dataset that is requested for issuance.
     * When this parameter is used, the [credentialConfigurationId] MUST NOT be present.
     */
    @SerialName("credential_identifier")
    val credentialIdentifier: String? = null,

    /**
     * OID4VCI: REQUIRED if a `credential_identifiers` parameter was not returned from the Token Response as part of
     * the `authorization_details` parameter (see [OpenIdAuthorizationDetails.credentialIdentifiers]).
     * It MUST NOT be used otherwise. String that uniquely identifies one of the keys in the name/value pairs stored
     * in the `credential_configurations_supported` Credential Issuer metadata
     * (see [IssuerMetadata.supportedCredentialConfigurations]).
     * The corresponding object in the `credential_configurations_supported` map MUST contain one of the value(s)
     * used in the `scope` parameter in the Authorization Request.
     * When this parameter is used, the [credentialIdentifier] MUST NOT be present.
     */
    @SerialName("credential_configuration_id")
    val credentialConfigurationId: String? = null,

    /**
     * OID4VCI: REQUIRED if an [OpenIdAuthorizationDetails] was not returned from the
     * [TokenResponseParameters] (e.g. when the credential was requested using a [AuthenticationRequestParameters.scope]
     * or a pre-authorisation code was used that did not return an [OpenIdAuthorizationDetails]).
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
     * OID4VCI: ISO mDL: OPTIONAL. Object as defined in Appendix A.2.2, see [SupportedCredentialFormat.isoClaims].
     *
     * OID4VCI: SD-JWT: OPTIONAL. An object as defined in Appendix A.3.2, see [SupportedCredentialFormat.sdJwtClaims].
     */
    @SerialName("claims")
    var claims: JsonElement? = null,

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

    /**
     * OID4VCI: ISO mDL: OPTIONAL. Object as defined in Appendix A.2.2, see [SupportedCredentialFormat.isoClaims].
     */
    val isoClaims: Map<String, Map<String, RequestedCredentialClaimSpecification>>?
        get() = claims?.let {
            runCatching {
                odcJsonSerializer.decodeFromJsonElement<Map<String, Map<String, RequestedCredentialClaimSpecification>>>(
                    it
                )
            }.getOrNull()
        }

    fun withIsoClaims(isoClaims: Map<String, Map<String, RequestedCredentialClaimSpecification>>) =
        this.copy(claims = odcJsonSerializer.encodeToJsonElement(isoClaims))

    /**
     * OID4VCI: SD-JWT: OPTIONAL. An object as defined in Appendix A.3.2, see [SupportedCredentialFormat.sdJwtClaims].
     */
    val sdJwtClaims: Map<String, RequestedCredentialClaimSpecification>?
        get() = claims?.let {
            runCatching {
                odcJsonSerializer.decodeFromJsonElement<Map<String, RequestedCredentialClaimSpecification>>(it)
            }.getOrNull()
        }

    fun withSdJwtClaims(sdJwtClaims: Map<String, RequestedCredentialClaimSpecification>) =
        this.copy(claims = odcJsonSerializer.encodeToJsonElement(sdJwtClaims))

    fun serialize() = odcJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<CredentialRequestParameters> =
            runCatching { odcJsonSerializer.decodeFromString<CredentialRequestParameters>(input) }.wrap()
    }

}
