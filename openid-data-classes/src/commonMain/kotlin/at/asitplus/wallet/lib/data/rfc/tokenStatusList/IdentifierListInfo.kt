package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

/**
 * DER encoded X509 Certificate
 */
private typealias Certificate = ByteArray


@Serializable
@SerialName("identifier_list")
data class IdentifierListInfo(
    @SerialName("id")
    @ByteString
    val identifier: ByteArray,
    @SerialName("uri")
    val uri: UniformResourceIdentifier,
    /**
     * The identifier_list and status_list in the MSO may contain the Certificate element. If the
     * Certificate element is present, it shall contain a certificate containing the public key that signed the
     * top-level certificate in the x5chain element in the MSO revocation list structure. The mdoc reader shall
     * use that certificate as trust point for verification of the x5chain element in the MSO revocation list
     * structure. If the Certificate element is not present, the top-level certificate in the x5chain element
     * shall be signed by the certificate used to sign the certificate in the x5chain element of the MSO. In the
     * context of an mDL, that is the IACA certificate.
     */
    @SerialName("certificate")
    @ByteString
    val certificate: Certificate? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IdentifierListInfo

        if (!identifier.contentEquals(other.identifier)) return false
        if (uri != other.uri) return false
        if (certificate != null) {
            if (other.certificate == null) return false
            if (!certificate.contentEquals(other.certificate)) return false
        } else if (other.certificate != null) {
            return false
        }

        return true
    }

    override fun hashCode(): Int {
        var result = identifier.contentHashCode()
        result = 31 * result + uri.hashCode()
        result = 31 * result + (certificate?.contentHashCode() ?: 0)
        return result
    }
}
