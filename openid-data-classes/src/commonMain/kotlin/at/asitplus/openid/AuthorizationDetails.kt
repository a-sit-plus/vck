package at.asitplus.openid

import at.asitplus.csc.collection_entries.DocumentLocation
import at.asitplus.csc.collection_entries.OAuthDocumentDigest
import at.asitplus.csc.enums.SignatureQualifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonElement

@Serializable
sealed class AuthorizationDetails

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
     * OID4VCI: REQUIRED. String specifying a unique identifier of the
     * Credential being described in [IssuerMetadata.supportedCredentialConfigurations].
     * The referenced object in [IssuerMetadata.supportedCredentialConfigurations] conveys the details, such as the
     * format and format-specific parameters like `vct` for SD-JWT VC or `doctype` for ISO mdoc.
     */
    @SerialName("credential_configuration_id")
    val credentialConfigurationId: String? = null,

    /**
     * OID4VCI: ISO mDL: OPTIONAL. An array of claims description objects as defined in Appendix B.2.
     * OID4VCI: IETF SD-JWT VC: OPTIONAL. An array of claims description objects as defined in Appendix B.2.
     */
    @SerialName("claims")
    val claimDescription: Set<ClaimDescription>? = null,

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
     * Note: Is only required in the token response!
     */
    @SerialName("credential_identifiers")
    val credentialIdentifiers: Set<String>? = null,
) : AuthorizationDetails() {

    @Transient
    @Deprecated("Use claimDescription instead")
    val claims: JsonElement? = null

}


/**
 * CSC-API v2.0.0.2
 * The authorization details type credential allows applications to pass the details of a certain
 * credential authorization in a single JSON object
 */
@Serializable
@SerialName("credential")
data class CscAuthorizationDetails(
    /**
     * The identifier associated to the credential to authorize
     */
    @SerialName("credentialID")
    val credentialID: String? = null,

    /**
     * This parameter contains the symbolic identifier determining the kind of
     * signature to be created
     */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,

    /**
     * An array composed of entries for every document to be signed. This applies for
     * array both cases, where are document is signed or a digest is signed
     */
    @SerialName("documentDigests")
    val documentDigests: Collection<OAuthDocumentDigest>,

    /**
     * String containing the OID of the hash algorithm used to generate the hashes
     * listed in documentDigests.
     */
    @SerialName("hashAlgorithmOID")
    @Serializable(ObjectIdentifierStringSerializer::class)
    val hashAlgorithmOid: ObjectIdentifier,

    /**
     * An array of strings designating the locations of
     * array the API where the access token issued in a certain OAuth transaction shall be used.
     */
    @SerialName("locations")
    val locations: Collection<String>? = null,

    /**
     * UC5 RQES Specification: This parameter is used to convey the
     * signer document. This parameter
     * SHALL not be used when the signer
     * document is not required for the
     * creation of the signature (for example,
     * in the Wallet-centric model)
     */
    @SerialName("documentLocations")
    val documentLocations: Collection<DocumentLocation>? = null,
) : AuthorizationDetails()