package at.asitplus.etsi

import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * The format of the PublicKeyValue component is left open and is syntax-specific
 */
interface PublicKeyValue

/**
 * The format of the SubjectKeyIdentifier component is left open and is syntax-specific
 */
interface SubjectKeyIdentifier

/**
 * The format of the OtherId component is left open
 */
interface OtherId

@Serializable
data class ServiceDigitalIdentity(
    /**
     * Base64-encoded X.509 public-key certificates identifying the service; unparseable entries become null (TS
     * 119 602, 6.6.3.1).
     */
    @SerialName(SerialNames.X509_CERTIFICATE)
    val x509Certificates: List<@Serializable(with = EtsiX509CertificateSerializer::class) X509Certificate?> = emptyList(),
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
        require( x509Certificates.isNotEmpty() || x509SKIs?.isNotEmpty() != false) {
            "Expected at least 1 X509Certificate or at least 1 X509SKI, but got 0."
        }
        require(x509SubjectNames?.isNotEmpty() != false) {
            "Expected at least 1 X509SubjectName, but got 0."
        }
        require(publicKeyValues?.isNotEmpty() != false) {
            "Expected at least 1 PublicKeyValue, but got 0."
        }
        require(otherIds?.isNotEmpty() != false) {
            "Expected at least 1 other id, but got 0."
        }
    }

    object SerialNames {
        /** Wire member name `SubjectKeyIdentifier`. */
        const val SUBJECT_KEY_IDENTIFIER = "SubjectKeyIdentifier"
        /** Wire member name `X509Certificates`. */
        const val X509_CERTIFICATE = "X509Certificates"
        /** Wire member name `PublicKeyValue`. */
        const val PUBLIC_KEY_VALUE = "PublicKeyValue"
        /** Wire member name `X509SubjectName`. */
        const val X509_SUBJECT_NAMES = "X509SubjectName"
        /** Wire member name `OtherId`. */
        const val OTHER_ID = "OtherId"
    }
}