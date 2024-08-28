package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VCI: The request parameter `authorization_details` defined in Section 2 of (RFC9396) MUST be used to convey the
 * details about the Credentials the Wallet wants to obtain. This specification introduces a new authorization details
 * type `openid_credential` and defines the following parameters to be used with this authorization details type.
 */
@Serializable
data class AuthorizationDetails(
    /**
     * OID4VCI: REQUIRED. String that determines the authorization details type. It MUST be set to `openid_credential`
     * for the purpose of this specification.
     */
    @SerialName("type")
    val type: String,

    /**
     * OID4VC: REQUIRED when [format] parameter is not present. String specifying a unique identifier of the Credential
     * being described in [IssuerMetadata.supportedCredentialConfigurations].
     */
    @SerialName("credential_configuration_id")
    val credentialConfigurationId: String? = null,

    /**
     * OID4VCI: REQUIRED when [credentialConfigurationId] parameter is not present.
     * String identifying the format of the Credential the Wallet needs.
     * This Credential format identifier determines further claims in the authorization details object needed to
     * identify the Credential type in the requested format.
     */
    @SerialName("format")
    val format: CredentialFormatEnum? = null,

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
     * Must contain an entry form [IssuerMetadata.authorizationServers].
     */
    @SerialName("locations")
    val locations: Set<String>? = null,

    /**
     * OID4VCI: OPTIONAL. Array of strings, each uniquely identifying a Credential that can be issued using the Access
     * Token returned in this response. Each of these Credentials corresponds to the same entry in the
     * [IssuerMetadata.supportedCredentialConfigurations] but can contain different claim values or a
     * different subset of claims within the claims set identified by that Credential type.
     * This parameter can be used to simplify the Credential Request, as defined in Section 7.2, where the
     * `credential_identifier` parameter replaces the format parameter and any other Credential format-specific
     * parameters in the Credential Request. When received, the Wallet MUST use these values together with an Access
     * Token in subsequent Credential Requests.
     */
    @SerialName("credential_identifiers")
    val credentialIdentifiers: Set<String>? = null,
)