package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialOffer(
    /**
     * OID4VCI: REQUIRED. The URL of the Credential Issuer, as defined in Section 11.2.1, from which the Wallet is
     * requested to obtain one or more Credentials. The Wallet uses it to obtain the Credential Issuer's Metadata
     * following the steps defined in Section 11.2.2.
     */
    @SerialName("credential_issuer")
    val credentialIssuer: String,

    /**
     * OID4VCI: REQUIRED. Array of unique strings that each identify one of the keys in the name/value pairs stored in
     * [IssuerMetadata.supportedCredentialConfigurations]. The Wallet uses these string values to
     * obtain the respective object that contains information about the Credential being offered as defined in
     * Section 11.2.3. For example, these string values can be used to obtain `scope` values to be used in the
     * Authorization Request, see [AuthenticationRequestParameters.scope].
     */
    @SerialName("credential_configuration_ids")
    val configurationIds: Set<String>,

    /**
     * OID4VCI: OPTIONAL. If [grants] is not present or is empty, the Wallet MUST determine the Grant Types the
     * Credential Issuer's Authorization Server supports using the respective metadata. When multiple grants are
     * present, it is at the Wallet's discretion which one to use.
     */
    @SerialName("grants")
    val grants: CredentialOfferGrants? = null,

    /**
     * Additional parameters for issuance via the Digital Credentials API, as per OID4VCI draft pull request
     * https://github.com/openid/OpenID4VCI/pull/476
     */

    /**
     * OID4VCI: REQUIRED for DC API. The Issuer's Credential Issuer Metadata object.
     */
    @SerialName("credential_issuer_metadata")
    val credentialIssuerMetadata: IssuerMetadata? = null,

    /**
     * OID4VCI: OPTIONAL and only for DC API. The Authorization Server metadata object as defined by Section 2 of [@!RFC8414].
     * When provided, the authorization_server parameter must not be present. TODO do they really mean authorization_server or actually authorization_servers? check with final spec
     */
    @SerialName("authorization_server_metadata")
    val authorizationServerMetadata: OAuth2AuthorizationServerMetadata? = null,
) {
    init {
        if (authorizationServerMetadata != null) {
            require(grants?.authorizationCode?.authorizationServer == null) { "authorization_server_metadata and authorization_server are mutually exclusive" }
        }
    }

    fun checkDcApiRequirements() {
        require(credentialIssuerMetadata != null) { "credential_issuer_metadata is required for DC API" }
    }
}