package at.asitplus.etsi

import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * JSON Web Key representation of a public key (TS 119 602, Annex A.1).
 */
typealias PublicKeyValue = JsonWebKey

/**
 * Base64 string identifying a public key (TS 119 602, Annex A.1).
 */
typealias SubjectKeyIdentifier = String

/**
 * String representation of another service identifier (TS 119 602, Annex A.1).
 */
typealias OtherId = String

@Serializable
data class ServiceDigitalIdentity(
    /**
     * Base64-encoded X.509 public-key certificates identifying the service; unparseable entries become null (TS
     * 119 602, 6.6.3.1).
     */
    @SerialName(SerialNames.X509_CERTIFICATE)
    @Serializable(with = EtsiX509CertificateListSerializer::class)
    val x509Certificates: List<X509Certificate?>? = null,
    /**
     * X.509 distinguished names identifying the service, preferably encoded according to RFC 4514 (TS 119 602,
     * 6.6.3.2).
     */
    @SerialName(SerialNames.X509_SUBJECT_NAMES)
    val x509SubjectNames: List<Rfc4514DistinguishedName>? = null,
    /** Public keys identifying the service and matching any listed certificates (TS 119 602, 6.6.3.3). */
    @SerialName(SerialNames.PUBLIC_KEY_VALUE)
    val publicKeyValues: List<PublicKeyValue>? = null,
    /** Identifiers of the public keys identifying the service (TS 119 602, 6.6.3.4). */
    @SerialName(SerialNames.SUBJECT_KEY_IDENTIFIER)
    val x509SKIs: List<SubjectKeyIdentifier>? = null,
    /** Additional service identifiers whose format is left open (TS 119 602, 6.6.3.5). */
    @SerialName(SerialNames.OTHER_ID)
    val otherIds: List<OtherId>? = null,
) {
    init {
        require(!x509Certificates.isNullOrEmpty() || !x509SKIs.isNullOrEmpty() ||
                !x509SubjectNames.isNullOrEmpty() || !publicKeyValues.isNullOrEmpty() || !otherIds.isNullOrEmpty()) {
            "Expected at least one service digital identifier."
        }
        require(x509Certificates?.isNotEmpty() != false) { "Expected non-empty X509Certificates when present." }
        require(x509SubjectNames?.isNotEmpty() != false) { "Expected non-empty X509SubjectNames when present." }
        require(publicKeyValues?.isNotEmpty() != false) { "Expected non-empty PublicKeyValues when present." }
        require(x509SKIs?.isNotEmpty() != false) { "Expected non-empty X509SKIs when present." }
        require(otherIds?.isNotEmpty() != false) { "Expected non-empty OtherIds when present." }
    }

    object SerialNames {
        /** Wire member name `X509SKIs`. */
        const val SUBJECT_KEY_IDENTIFIER = "X509SKIs"
        /** Wire member name `X509Certificates`. */
        const val X509_CERTIFICATE = "X509Certificates"
        /** Wire member name `PublicKeyValues`. */
        const val PUBLIC_KEY_VALUE = "PublicKeyValues"
        /** Wire member name `X509SubjectNames`. */
        const val X509_SUBJECT_NAMES = "X509SubjectNames"
        /** Wire member name `OtherIds`. */
        const val OTHER_ID = "OtherIds"
    }
}