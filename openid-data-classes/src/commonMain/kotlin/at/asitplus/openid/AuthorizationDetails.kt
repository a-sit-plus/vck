package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement

interface AuthorizationDetails

/**
 * OID4VCI: The request parameter `authorization_details` defined in Section 2 of (RFC9396) MUST be used to convey
 * the details about the Credentials the Wallet wants to obtain. This specification introduces a new authorization
 * details type `openid_credential` and defines the following parameters to be used with this authorization details
 * type.
 */
@Serializable
@SerialName("openid_credential")
data class OpenIdAuthorizationDetails(
    /**
     * OID4VCI: REQUIRED when [format] parameter is not present. String specifying a unique identifier of the
     * Credential being described in [IssuerMetadata.supportedCredentialConfigurations].
     * The referenced object in [IssuerMetadata.supportedCredentialConfigurations] conveys the details, such as the
     * format, for issuance of the requested Credential.
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
     * Credential Issuer. It MUST only be present if the [format] claim is present. It MUST not be present
     * otherwise.
     */
    @SerialName("doctype")
    val docType: String? = null,

    /**
     * OID4VCI: ISO mDL: OPTIONAL. An array of claims description objects as defined in Appendix B.2.
     * OID4VCI: IETF SD-JWT VC: OPTIONAL. An array of claims description objects as defined in Appendix B.2.
     */
    @SerialName("claims")
    val claims: JsonElement? = null,

    /**
     * OID4VCI: W3C VC: OPTIONAL. Object containing a detailed description of the Credential consisting of the
     * following parameters, see [SupportedCredentialFormatDefinition].
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
     * OID4VCI: If the Credential Issuer metadata contains an [IssuerMetadata.authorizationServers] parameter, the
     * authorization detail's locations common data field MUST be set to the Credential Issuer Identifier value.
     */
    @SerialName("locations")
    val locations: Set<String>? = null,

    /**
     * OID4VCI: REQUIRED. Array of strings, each uniquely identifying a Credential Dataset that can be issued using
     * the Access Token returned in this response. Each of these Credential Datasets corresponds to the same
     * Credential Configuration in the [IssuerMetadata.supportedCredentialConfigurations]. The Wallet MUST use these
     * identifiers together with an Access Token in subsequent Credential Requests.
     */
    @SerialName("credential_identifiers")
    val credentialIdentifiers: Set<String>,
) : AuthorizationDetails {

    val claimDescription: Set<ClaimDescription>?
        get() = claims?.let {
            runCatching {
                odcJsonSerializer.decodeFromJsonElement<Set<ClaimDescription>>(it)
            }.getOrNull()
        }

}