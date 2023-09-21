package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.asn1.sequence
import kotlinx.datetime.Instant

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed
 */
data class TbsCertificate(
    val version: Int = 2,
    val serialNumber: Long,
    val signatureAlgorithm: JwsAlgorithm,
    val issuerCommonName: String,
    val validFrom: Instant,
    val validUntil: Instant,
    val subjectCommonName: String,
    val publicKey: CryptoPublicKey
) {
    fun encodeToDer() = sequence {
        version { version }
        long { serialNumber }
        sigAlg { signatureAlgorithm }
        sequence {
            set {
                sequence {
                    commonName { issuerCommonName }
                }
            }
        }
        sequence {
            utcTime { validFrom }
            utcTime { validUntil }
        }
        sequence {
            set {
                sequence {
                    commonName { subjectCommonName }
                }
            }
        }
        subjectPublicKey { publicKey }
    }
}

/**
 * Very simple implementation of an X.509 Certificate
 */
data class X509Certificate(
    val tbsCertificate: TbsCertificate,
    val signatureAlgorithm: JwsAlgorithm,
    val signature: ByteArray
) {
    fun encodeToDer() = sequence {
        tbsCertificate { tbsCertificate }
        sigAlg { signatureAlgorithm }
        bitString { signature }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X509Certificate

        if (tbsCertificate != other.tbsCertificate) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCertificate.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

