package at.asitplus.rqes.collection_entries

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * JsonObject which is part of [CredentialInfo]
 */
@Serializable
data class CscCertificateParameters(
    /**
     * The status of validity of the end entity certificate.
     */
    @SerialName("status")
    val status: CertStatus? = null,

    /**
     * One or more Base64-encoded X.509v3 certificates from the certificate
     * Conditional
     * chain. If the certificates parameter is “chain”, the entire certificate chain
     * SHALL be returned with the end entity certificate at the beginning of the
     * array. If the certificates parameter is “single”, only the end entity
     * certificate SHALL be returned. If the certificates parameter is “none”, this
     * value SHALL NOT be returned.
     */
    //TODO base64 certificate serializer
    @SerialName("certificates")
    val certificates: List<String>? = null,

    /**
     * The Issuer Distinguished Name from the X.509v3 end entity certificate as
     * UTF-8-encoded character string according to RFC 4514. This value
     * SHALL be returned when certInfo is “true”.
     */
    @SerialName("issuerDN")
    val issuerDN: String? = null,

    /**
     * The Serial Number from the X.509v3 end entity certificate represented
     * as hex-encoded string format. This value SHALL be returned when
     * certInfo is “true”.
     */
    @SerialName("serialNumber")
    val serialNumber: String? = null,

    /**
     * The Subject Distinguished Name from the X.509v3 end entity certificate
     * as UTF-8-encoded character string, according to RFC 4514 [4]. This value
     * SHALL be returned when certInfo is “true”.
     */
    @SerialName("subjectDN")
    val subjectDN: String? = null,

    /**
     * The validity start date from the X.509v3 end entity certificate as
     * character string, encoded as GeneralizedTime (RFC 5280 [8])
     * (e.g. “YYYYMMDDHHMMSSZ”). This value SHALL be returned when
     * certInfo is “true”.
     */
    @SerialName("validFrom")
    val validFrom: String? = null,

    /**
     * The validity end date from the X.509v3 end entity certificate as character
     * string, encoded as GeneralizedTime (RFC 5280 [8])
     * (e.g. “YYYYMMDDHHMMSSZ”). This value SHALL be returned when
     * certInfo is “true”.
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