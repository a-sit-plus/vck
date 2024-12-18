package at.asitplus.rqes

import at.asitplus.rqes.collection_entries.CscAuthParameter
import at.asitplus.rqes.collection_entries.CscCertificateParameters
import at.asitplus.rqes.collection_entries.CscKeyParameters
import at.asitplus.rqes.enums.SignatureQualifier
import kotlinx.serialization.SerialName

/**
 * In case of credentials/list [credentialID] is REQUIRED
 * in case this is a credentials/info response [credentialID] MUST NOT be in it...
 * TODO presumably make credentialID nullable and make client check when calling credential/list manually
 */
data class CredentialInfo(
    @SerialName("credentialID")
    val credentialID: String? = null,

    @SerialName("description")
    val description: String? = null,

    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,

    @SerialName("key")
    val keyParameters: CscKeyParameters,

    @SerialName("cert")
    val certParameters: CscCertificateParameters? = null,

    @SerialName("auth")
    val authParameters: CscAuthParameter? = null,

    @SerialName("SCAL")
    val scal: ScalOptions,

    @SerialName("multisign")
    val multisign: UInt,

    @SerialName("lang")
    val lang: String? = null,
) {
    enum class ScalOptions {
        @SerialName("1")
        SCAL1,

        @SerialName("2")
        SCAL2,
    }
}