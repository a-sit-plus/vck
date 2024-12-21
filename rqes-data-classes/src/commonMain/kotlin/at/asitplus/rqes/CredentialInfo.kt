package at.asitplus.rqes

import at.asitplus.openid.SignatureQualifier
import at.asitplus.rqes.collection_entries.CscAuthParameter
import at.asitplus.rqes.collection_entries.CscCertificateParameters
import at.asitplus.rqes.collection_entries.CscKeyParameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * In case of credentials/list [credentialID] is REQUIRED
 * in case this is a credentials/info response [credentialID] MUST NOT be in it...
 */
@Serializable
data class CredentialInfo(
    /**
     * The credentialID identifying one of the credentials associated with the
     * provided or implicit userID.
     * MUST be present in `credential/list` request but MUST NOT be present in `credential/info` request
     */
    @SerialName("credentialID")
    val credentialID: String? = null,

    /**
     * A free form description of the credential in the lang language. The
     * maximum size of the string is 255 characters.
     */
    @SerialName("description")
    val description: String? = null,

    /**
     * Identifier qualifying the type of signature this credential is suitable for
     */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,

    /**
     * Status and attributes of key
     */
    @SerialName("key")
    val keyParameters: CscKeyParameters,

    /**
     * Details of the requested certificate in case [CredentialListRequestParameters]
     */
    @SerialName("cert")
    val certParameters: CscCertificateParameters? = null,


    /**
     * Details about the authentication method
     */
    @SerialName("auth")
    val authParameters: CscAuthParameter,

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