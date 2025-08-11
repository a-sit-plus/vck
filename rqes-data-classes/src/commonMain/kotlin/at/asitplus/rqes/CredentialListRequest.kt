package at.asitplus.rqes

import at.asitplus.rqes.enums.CertificateOptions
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class that implements credentialInfo defined
 * in CSC-API v2.0.0.2 Ch. 11.4 "credentials/list" and Ch. 11.5 "credentials/info"
 */
@Serializable
@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.csc.CredentialListRequest"))
data class CredentialListRequest(
    /**
     * CSC REQUIRED-CONDITIONAL.
     * The identifier associated to the identity of the credential owner. This parameter
     * SHALL NOT be present if the service authorization is user-specific (see NOTE below).
     * In that case the userID is already implicit in the service access token passed in the
     * Authorization header.
     */
    @SerialName("userID")
    val userID: String? = null,

    /**
     * CSC OPTIONAL.
     * Request to return the main information included in the public key certificate and
     * the public key certificate itself or the certificate chain associated to the credentials.
     * The default value is [Boolean.false]
     */
    @SerialName("credentialInfo")
    val credentialInfo: Boolean? = false,

    /**
     * CSC OPTIONAL-CONDITIONAL.
     * Specifies which certificates from the certificate chain SHALL be returned
     * The default value is [CertificateOptions.SINGLE]
     */
    @SerialName("certificates")
    val certificates: CertificateOptions? = CertificateOptions.SINGLE,

    /**
     * Request to return various parameters containing information from the end entity
     * certificate(s).
     * The default value is [Boolean.false]
     */
    @SerialName("certInfo")
    val certInfo: Boolean? = false,

    /**
     * Request to return various parameters containing information on the authorization
     * mechanisms supported by the corresponding credential (auth group).
     * The default value is “false”
     */
    @SerialName("authInfo")
    val authInfo: Boolean? = false,

    /**
     * Request to return only credentials usable to create a valid signature.
     * The default value is “false”
     */
    @SerialName("onlyValid")
    val onlyValid: Boolean? = false,

    /**
     * Request a preferred language of the response to the remote service
     */
    @SerialName("lang")
    val lang: String? = null,

    /**
     * Arbitrary data from the signature application. It can be used to handle a
     * transaction identifier or other application-spe cific data that may be useful for
     * debugging purposes
     */
    @SerialName("clientData")
    val clientData: String? = null,
)
