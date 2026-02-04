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
     * Additional Credential Offer parameters MAY be defined and used. The Wallet MUST ignore any unrecognized
     * parameters. Practical DC API Issuing implementations send the authorization_server_metadata and
     * credential_issuer_metadata with the credential offer.
     */
    @SerialName("authorization_server_metadata")
    val authorizationServerMetadata: OAuth2AuthorizationServerMetadata? = null,

    @SerialName("credential_issuer_metadata")
    val credentialIssuerMetadata: IssuerMetadata? = null,
) {
    init {
        if (authorizationServerMetadata != null) {
            require(grants?.authorizationCode?.authorizationServer == null)
        }
    }
}