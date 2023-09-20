package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.jws.JwsExtensions.encodeToByteArray
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.datetime.Instant

data class TbsCertificate(
    val version: Int = 2,
    val serialNumber: Long,
    val signatureAlgorithm: JwsAlgorithm,
    val issuer: String,
    val validFrom: Instant,
    val validUntil: Instant,
    val subject: String,
    val subjectPublicKey: CryptoPublicKey
) {
    fun encodeToDer(): ByteArray {
        return (version.encodeAsVersion() +
                serialNumber.encodeToDer() +
                signatureAlgorithm.encodeToDer() +
                issuer.encodeAsCommonName() +
                (validFrom.encodeToDer() + validUntil.encodeToDer()).sequence() +
                subject.encodeAsCommonName() +
                subjectPublicKey.encodeToDer())
            .sequence()
    }
}

data class X509Certificate(
    val tbsCertificate: TbsCertificate,
    val signatureAlgorithm: JwsAlgorithm,
    val signature: ByteArray
) {
    fun encodeToDer(): ByteArray {
        return (tbsCertificate.encodeToDer() +
                signatureAlgorithm.encodeToDer() +
                signature.encodeAsBitString()).sequence()
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

private fun String.encodeAsCommonName(): ByteArray {
    return ("550403".decodeToByteArray(Base16()).oid() + this.encodeToDer()).sequence().set().sequence()
}

private fun Int.encodeAsVersion(): ByteArray = encodeToDer().wrapInAsn1Tag(0xA0.toByte())

private fun Int.encodeToDer(): ByteArray =
    encodeToByteArray().dropWhile { it == 0.toByte() }.toByteArray().wrapInAsn1Tag(0x02)

private fun Long.encodeToDer(): ByteArray =
    encodeToByteArray().dropWhile { it == 0.toByte() }.toByteArray().wrapInAsn1Tag(0x02)

private fun CryptoPublicKey.encodeToDer(): ByteArray = when (this) {
    is CryptoPublicKey.Ec -> this.encodeToDer()
}

private fun CryptoPublicKey.Ec.encodeToDer(): ByteArray {
    val ecKeyTag = "2A8648CE3D0201".decodeToByteArray(Base16()).oid()
    val ecEncryptionNullTag = "2A8648CE3D030107".decodeToByteArray(Base16()).oid()
    val content = (byteArrayOf(0x04.toByte()) + x + y).encodeAsBitString()
    return ((ecKeyTag + ecEncryptionNullTag).sequence() + content).sequence()
}

private fun ByteArray.encodeAsBitString(): ByteArray = (byteArrayOf(0x00) + this).wrapInAsn1Tag(0x03)

private fun String.encodeToDer(): ByteArray = this.encodeToByteArray().wrapInAsn1Tag(0x0c)

private fun Instant.encodeToDer(): ByteArray {
    val matchResult =
        Regex("[0-9]{2}([0-9]{2})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\\.([0-9]+)Z")
            .matchEntire(toString())
            ?: throw IllegalArgumentException("instant serialization failed: $this")
    val year = matchResult.groups[1]?.value ?: throw IllegalArgumentException("instant serialization year failed: $this")
    val month = matchResult.groups[2]?.value ?: throw IllegalArgumentException("instant serialization month failed: $this")
    val day = matchResult.groups[3]?.value ?: throw IllegalArgumentException("instant serialization day failed: $this")
    val hour = matchResult.groups[4]?.value ?: throw IllegalArgumentException("instant serialization hour failed: $this")
    val minute = matchResult.groups[5]?.value ?: throw IllegalArgumentException("instant serialization minute failed: $this")
    val seconds = matchResult.groups[6]?.value ?: throw IllegalArgumentException("instant serialization seconds failed: $this")
    val string = "$year$month$day$hour$minute${seconds}Z"
    return string.encodeToByteArray().wrapInAsn1Tag(0x17)
}

private fun JwsAlgorithm.encodeToDer(): ByteArray {
    return when (this) {
        JwsAlgorithm.ES256 -> "2A8648CE3D040302".decodeToByteArray(Base16()).oid().sequence()
        else -> TODO()
    }
}

private fun ByteArray.sequence() = this.wrapInAsn1Tag(0x30)

private fun ByteArray.set() = this.wrapInAsn1Tag(0x31)

private fun ByteArray.oid() = this.wrapInAsn1Tag(0x06)

private fun ByteArray.wrapInAsn1Tag(tag: Byte): ByteArray {
    return byteArrayOf(tag) + this.size.encodeLength() + this
}

private fun Int.encodeLength(): ByteArray {
    if (this < 128) {
        return byteArrayOf(this.toByte())
    }
    if (this < 0x100) {
        return byteArrayOf(0x81.toByte(), this.toByte())
    }
    if (this < 0x8000) {
        return byteArrayOf(0x82.toByte(), (this ushr 8).toByte(), this.toByte())
    }
    throw IllegalArgumentException("length $this")
}
