package at.asitplus.rqes.collection_entries

import kotlinx.serialization.SerialName

data class CscCertificateParameters(
    val certStatus: CertStatus? = null,
    val certCertificates: List<String>? = null,
    val certIssuerDN: String? = null,
    val certSerialNumber: String? = null,
    val certSubjectDN: String? = null,
    val certValidFrom: String? = null,
    val certValidTo: String? = null,
) {
    enum class CertStatus {
        @SerialName("valid")
        VALID,

        @SerialName("expired")
        EXPIRED,

        @SerialName("revoked")
        REVOKED,

        @SerialName("suspended")
        SUSPENDED
    }
}