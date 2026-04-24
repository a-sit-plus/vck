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
    @SerialName(SerialNames.X509_CERTIFICATE)
    val x509Certificates: List<@Serializable(with = EtsiX509CertificateSerializer::class) X509Certificate>? = null,
    @SerialName(SerialNames.X509_SUBJECT_NAMES)
    val x509SubjectNames: List<Rfc4514DistinguishedName>? = null,
    @SerialName(SerialNames.PUBLIC_KEY_VALUE)
    val publicKeyValues: List<PublicKeyValue>? = null,
    @SerialName(SerialNames.SUBJECT_KEY_IDENTIFIER)
    val x509SKIs: List<SubjectKeyIdentifier>? = null,
    @SerialName(SerialNames.OTHER_ID)
    val otherIds: List<OtherId>? = null,
) {
    init {
        require(x509Certificates?.isNotEmpty() != false) {
            "Expected at least 1 X509Certificate, but got 0."
        }
        require(x509SubjectNames?.isNotEmpty() != false) {
            "Expected at least 1 X509SubjectName, but got 0."
        }
        require(publicKeyValues?.isNotEmpty() != false) {
            "Expected at least 1 PublicKeyValue, but got 0."
        }
        require(x509SKIs?.isNotEmpty() != false) {
            "Expected at least 1 X509SKI, but got 0."
        }
        require(otherIds?.isNotEmpty() != false) {
            "Expected at least 1 other id, but got 0."
        }
    }

    object SerialNames {
        const val SUBJECT_KEY_IDENTIFIER = "SubjectKeyIdentifier"
        const val X509_CERTIFICATE = "X509Certificates"
        const val PUBLIC_KEY_VALUE = "PublicKeyValue"
        const val X509_SUBJECT_NAMES = "X509SubjectName"
        const val OTHER_ID = "OtherId"
    }
}