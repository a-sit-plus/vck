package at.asitplus.rqes

import at.asitplus.rqes.enums.CertificateOptions
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialInfoRequest(
    /**
     * The unique identifier associated to the credential.
     */
    @SerialName("credentialID")
    val credentialID: String,

    /**
     * Specifies which certificates from the certificate chain SHALL be returned
     * The default value is “single”
     */
    @SerialName("certificates")
    val certificates: CertificateOptions? = null,

    /**
     * Request to return various parameters containing information from the end entity
     * certificate(s).
     * The default value is “false”
     */
    @SerialName("certInfo")
    val certInfo: Boolean? = null,
    /**
     * Request to return various parameters containing information on the authorization
     * mechanisms supported by the corresponding credential (auth group).
     * The default value is “false”
     */
    @SerialName("authInfo")
    val authInfo: Boolean? = null,

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