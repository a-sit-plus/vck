package at.asitplus.openid

import at.asitplus.rqes.collection_entries.DocumentLocation
import at.asitplus.rqes.collection_entries.OAuthDocumentDigest
import at.asitplus.rqes.enums.SignatureQualifierEnum
import at.asitplus.signum.indispensable.asn1.ObjectIdSerializer
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray


@Serializable
sealed class AuthorizationDetails {
    /**
     * OID4VCI: The request parameter `authorization_details` defined in Section 2 of (RFC9396) MUST be used to convey
     * the details about the Credentials the Wallet wants to obtain. This specification introduces a new authorization
     * details type `openid_credential` and defines the following parameters to be used with this authorization details
     * type.
     */
    @Serializable
    @SerialName("openid_credential")
    data class OpenIdCredential(
        /**
         * OID4VCI: REQUIRED when [format] parameter is not present. String specifying a unique identifier of the
         * Credential being described in [IssuerMetadata.supportedCredentialConfigurations].
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
         * OID4VCI: ISO mDL: OPTIONAL. Object as defined in Appendix A.3.2 excluding the `display` and `value_type`
         * parameters. The `mandatory` parameter here is used by the Wallet to indicate to the Issuer that it only
         * accepts Credential(s) issued with those claim(s).
         */
        @SerialName("claims")
        val claims: Map<String, Map<String, RequestedCredentialClaimSpecification>>? = null,

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
        // TODO is required in OID4VCI!
        @SerialName("credential_identifiers")
        val credentialIdentifiers: Set<String>
    ) : AuthorizationDetails()

    /**
     * CSC: The authorization details type credential allows applications to pass the details of a certain
     * credential authorization in a single JSON object
     */
    @Serializable
    @SerialName("credential")
    data class CSCCredential(
        /**
         * CSC: The identifier associated to the credential to authorize
         */
        @SerialName("credentialID")
        val credentialID: String? = null,

        /**
         * CSC: This parameter contains the symbolic identifier determining the kind of
         * signature to be created
         */
        @SerialName("signatureQualifier")
        val signatureQualifier: SignatureQualifierEnum? = null,

        /**
         * CSC: An array composed of entries for every document to be signed. This applies for
         * array both cases, where are document is signed or a digest is signed
         */
        @SerialName("documentDigests")
        val documentDigests: Collection<OAuthDocumentDigest>,

        /**
         * CSC: String containing the OID of the hash algorithm used to generate the hashes
         * listed in documentDigests.
         */
        @SerialName("hashAlgorithmOID")
        @Serializable(ObjectIdSerializer::class)
        val hashAlgorithmOid: ObjectIdentifier,

        /**
         * CSC: An array of strings designating the locations of
         * array the API where the access token issued in a certain OAuth transaction shall be used.
         */
        @SerialName("locations")
        val locations: Collection<String>? = null,

        /**
         * QES: This parameter is used to convey the
         * signer document. This parameter
         * SHALL not be used when the signer
         * document is not required for the
         * creation of the signature (for example,
         * in the Wallet-centric model)
         */
        @SerialName("documentLocations")
        val documentLocations: Collection<DocumentLocation>,
    ) : AuthorizationDetails()

    companion object {
        fun parse(input: String): List<AuthorizationDetails> =
            jsonSerializer.decodeFromString<JsonArray>(input).map {
                jsonSerializer.decodeFromJsonElement(
                    serializer(),
                    it
                )
            }
    }
}