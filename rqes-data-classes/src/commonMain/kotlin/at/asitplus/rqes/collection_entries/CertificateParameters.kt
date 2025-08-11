package at.asitplus.rqes.collection_entries

import at.asitplus.rqes.serializers.Base64X509CertificateSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.rqes.enums.CertificateOptions
import at.asitplus.rqes.CredentialInfo
import at.asitplus.rqes.CredentialInfoRequest
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * CSC-API v2.0.0.2
 * JsonObject which is part of [CredentialInfo]
 */
@Serializable
@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.csc.collection_entries.CertificateParameters"))
data class CertificateParameters(
    /**
     * OPTIONAL.
     * The status of validity of the end entity certificate.
     */
    @SerialName("status")
    val status: CertStatus? = null,

    /**
     * REQUIRED-CONDITIONAL.
     * One or more Base64-encoded X.509v3 certificates from the certificate
     * chain. If [CredentialInfoRequest.certificates] is [CertificateOptions.CHAIN], the entire certificate chain
     * SHALL be returned with the end entity certificate at the beginning of the
     * array. If [CredentialInfoRequest.certificates] is [CertificateOptions.SINGLE], only the end entity
     * certificate SHALL be returned. If [CredentialInfoRequest.certificates] is [CertificateOptions.NONE], this
     * value SHALL NOT be returned.
     */
    @SerialName("certificates")
    val certificates: List<@Serializable(with = Base64X509CertificateSerializer::class) X509Certificate>? = null,

    /**
     * REQUIRED-CONDITIONAL.
     * The Issuer Distinguished Name from the X.509v3 end entity certificate as
     * UTF-8-encoded character string according to RFC 4514. This value
     * SHALL be returned when [CredentialInfoRequest.certInfo] is [Boolean.true].
     */
    @SerialName("issuerDN")
    val issuerDN: String? = null,

    /**
     * REQUIRED-CONDITIONAL.
     * The Serial Number from the X.509v3 end entity certificate represented
     * as hex-encoded string format. This value SHALL be returned when
     * [CredentialInfoRequest.certInfo] is [Boolean.true].
     */
    @SerialName("serialNumber")
    val serialNumber: String? = null,

    /**
     * REQUIRED-CONDITIONAL.
     * The Subject Distinguished Name from the X.509v3 end entity certificate
     * as UTF-8-encoded character string, according to RFC 4514 [4]. This value
     * SHALL be returned when [CredentialInfoRequest.certInfo] is [Boolean.true]..
     */
    @SerialName("subjectDN")
    val subjectDN: String? = null,

    /**
     * REQUIRED-CONDITIONAL.
     * The validity start date from the X.509v3 end entity certificate as
     * character string, encoded as GeneralizedTime (RFC 5280 [8])
     * (e.g. “YYYYMMDDHHMMSSZ”). This value SHALL be returned when
     * [CredentialInfoRequest.certInfo] is [Boolean.true]..
     */
    @SerialName("validFrom")
    val validFrom: String? = null,

    /**
     * REQUIRED-CONDITIONAL.
     * The validity end date from the X.509v3 end entity certificate as character
     * string, encoded as GeneralizedTime (RFC 5280 [8])
     * (e.g. “YYYYMMDDHHMMSSZ”). This value SHALL be returned when
     * [CredentialInfoRequest.certInfo] is [Boolean.true]..
     */
    @SerialName("validTo")
    val validTo: String? = null,
) {

    /**
     * Valid certificate statuses as defined in CSC v2.0.0.2
     */
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