package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.asn1.bitString
import at.asitplus.wallet.lib.asn1.commonName
import at.asitplus.wallet.lib.asn1.int
import at.asitplus.wallet.lib.asn1.long
import at.asitplus.wallet.lib.asn1.sequence
import at.asitplus.wallet.lib.asn1.set
import at.asitplus.wallet.lib.asn1.sigAlg
import at.asitplus.wallet.lib.asn1.subjectPublicKey
import at.asitplus.wallet.lib.asn1.tag
import at.asitplus.wallet.lib.asn1.tbsCertificate
import at.asitplus.wallet.lib.asn1.utcTime
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
        listOf(
            tag(0xA0) {
                int { version }
            },
            long { serialNumber },
            sigAlg { signatureAlgorithm },
            sequence {
                listOf(set {
                    listOf(sequence {
                        listOf(commonName { issuerCommonName })
                    })
                })
            },
            sequence {
                listOf(
                    utcTime { validFrom },
                    utcTime { validUntil }
                )
            },
            sequence {
                listOf(set {
                    listOf(sequence {
                        listOf(commonName { subjectCommonName })
                    })
                })
            },
            subjectPublicKey { publicKey }
        )
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
        listOf(
            tbsCertificate { tbsCertificate },
            sigAlg { signatureAlgorithm },
            bitString { signature }
        )
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

