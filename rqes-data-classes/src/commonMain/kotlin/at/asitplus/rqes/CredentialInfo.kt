package at.asitplus.rqes

import at.asitplus.openid.SignatureQualifier
import at.asitplus.rqes.collection_entries.AuthParameter
import at.asitplus.rqes.collection_entries.CertificateParameters
import at.asitplus.rqes.collection_entries.KeyParameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class that implements credentialInfo class defined
 * in CSC-API v2.0.0.2 Ch. 11.4 "credentials/list" and Ch. 11.5 "credentials/info"
 */
@Serializable
data class CredentialInfo(
    /**
     * CSC
     * In case of credentials/list [credentialID] is REQUIRED.
     * In case this is a credentials/info response [credentialID] is not defined.
     *
     * The credentialID identifying one of the credentials associated with the
     * provided or implicit userID.
     * MUST be present in `credential/list` request but MUST NOT be present in `credential/info` request
     */
    @SerialName("credentialID")
    val credentialID: String? = null,

    /**
     * CSC OPTIONAL.
     * A free form description of the credential in the lang language. The
     * maximum size of the string is 255 characters.
     */
    @SerialName("description")
    val description: String? = null,

    /**
     * CSC OPTIONAL.
     * Identifier qualifying the type of signature this credential is suitable for
     */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,

    /**
     * CSC REQUIRED.
     * Status and attributes of key.
     */
    @SerialName("key")
    val keyParameters: KeyParameters,

    /**
     * CSC REQUIRED-CONDITIONAL.
     * May be required depending on the [CredentialInfoRequest]
     * Contains information about the certificate associated with the credential
     */
    @SerialName("cert")
    val certParameters: CertificateParameters? = null,

    /**
     *
     * Details about the authentication method
     */
    @SerialName("auth")
    val authParameters: AuthParameter? = null,

    /**
     * Specifies if the RSSP will generate for this credential a signature
     * activation data (SAD) or an access token with scope “credential” that
     * contains a link to the hash to-be-signed
     * This value is OPTIONAL and the default value is “1”.
     */
    @SerialName("SCAL")
    val scal: ScalOptions? = ScalOptions.SCAL1,

    /**
     * A number equal or higher to 1 representing the maximum number of
     * signatures that can be created with this credential with a single
     * authorization request
     */
    @SerialName("multisign")
    val multisign: UInt,

    /**
     * Preferred language
     */
    @SerialName("lang")
    val lang: String? = null,
) {
    enum class ScalOptions {
        /**
         * “1”: The hash to-be-signed is not linked to the signature
         * activation data.
         */
        @SerialName("1")
        SCAL1,

        /**
         * “2”: The hash to-be-signed is linked to the signature activation
         * data.
         */
        @SerialName("2")
        SCAL2,
    }
}