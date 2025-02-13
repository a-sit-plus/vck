import at.asitplus.openid.AuthorizationDetails
import at.asitplus.rqes.collection_entries.DocumentLocation
import at.asitplus.rqes.collection_entries.OAuthDocumentDigest
import at.asitplus.openid.SignatureQualifier
import at.asitplus.signum.indispensable.asn1.ObjectIdSerializer
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * CSC: The authorization details type credential allows applications to pass the details of a certain
 * credential authorization in a single JSON object
 */
@Serializable
@SerialName("credential")
data class CscAuthorizationDetails(
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
    val signatureQualifier: SignatureQualifier? = null,

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
    val documentLocations: Collection<DocumentLocation>? = null,
) : AuthorizationDetails
