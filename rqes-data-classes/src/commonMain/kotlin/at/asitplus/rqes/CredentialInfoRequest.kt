package at.asitplus.rqes

import at.asitplus.rqes.enums.CertificateOptions
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class that implements request data class defined
 * in CSC-API v2.0.0.2 Ch. 11.5 "credentials/info"
 */
@Serializable
@Deprecated(
    "Module will be removed in the future", ReplaceWith(
        "CredentialInfoRequest",
        imports = ["at.asitplus.csc.CredentialInfoRequest"]
    )
)
data class CredentialInfoRequest(
    /**
     * CSC REQUIRED.
     * The unique identifier associated to the credential.
     */
    @SerialName("credentialID")
    val credentialID: String,

    /**
     * CSC OPTIONAL-CONDITIONAL.
     * Specifies which certificates from the certificate chain SHALL be returned
     * The default value is [CertificateOptions.SINGLE]
     */
    @SerialName("certificates")
    val certificates: CertificateOptions? = CertificateOptions.SINGLE,

    /**
     * CSC OPTIONAL.
     * Request to return various parameters containing information from the end entity
     * certificate(s).
     * The default value is [Boolean.false]
     */
    @SerialName("certInfo")
    val certInfo: Boolean? = false,

    /**
     * CSC OPTIONAL.
     * Request to return various parameters containing information on the authorization
     * mechanisms supported by the corresponding credential (auth group).
     * The default value is [Boolean.false]
     */
    @SerialName("authInfo")
    val authInfo: Boolean? = false,

    /**
     * CSC OPTIONAL.
     * Request a preferred language of the response to the remote service
     */
    @SerialName("lang")
    val lang: String? = null,

    /**
     * CSC OPTIONAL.
     * Arbitrary data from the signature application. It can be used to handle a
     * transaction identifier or other application-specific data that may be useful for
     * debugging purposes
     */
    @SerialName("clientData")
    val clientData: String? = null,
)