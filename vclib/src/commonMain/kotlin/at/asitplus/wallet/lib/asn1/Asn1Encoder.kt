package at.asitplus.wallet.lib.asn1

import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.jws.JwsAlgorithm
import at.asitplus.wallet.lib.jws.JwsExtensions.encodeToByteArray
import at.asitplus.wallet.lib.jws.TbsCertificate
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.datetime.Instant


fun tag(tag: Int, block: () -> ByteArray): ByteArray {
    val value = block()
    return byteArrayOf(tag.toByte()) + value.size.encodeLength() + value
}

fun long(block: () -> Long) = tag(0x02) { block().encodeToByteArray().dropWhile { it == 0.toByte() }.toByteArray() }

fun int(block: () -> Int) = tag(0x02) { block().encodeToByteArray().dropWhile { it == 0.toByte() }.toByteArray() }

fun bitString(block: () -> ByteArray) = tag(0x03) { (byteArrayOf(0x00) + block()) }

fun oid(block: () -> String): ByteArray = tag(0x06) { block().decodeToByteArray(Base16()) }

fun sequence(block: () -> List<ByteArray>) = tag(0x30) { block().fold(byteArrayOf()) { acc, bytes -> acc + bytes } }

fun set(block: () -> List<ByteArray>) = tag(0x31) { block().fold(byteArrayOf()) { acc, bytes -> acc + bytes } }

fun utf8String(block: () -> String) = tag(0x0c) { block().encodeToByteArray() }

fun commonName(block: () -> String) = oid { "550403" } + utf8String { block() }

fun subjectPublicKey(block: () -> CryptoPublicKey) = when (val value = block()) {
    is CryptoPublicKey.Ec -> value.encodeToDer()
    is CryptoPublicKey.Rsa -> TODO()
}

fun utcTime(block: () -> Instant): ByteArray {
    val value = block()
    val matchResult = Regex("[0-9]{2}([0-9]{2})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})")
        .matchAt(value.toString(), 0)
        ?: throw IllegalArgumentException("instant serialization failed: ${value}")
    val year = matchResult.groups[1]?.value
        ?: throw IllegalArgumentException("instant serialization year failed: ${value}")
    val month = matchResult.groups[2]?.value
        ?: throw IllegalArgumentException("instant serialization month failed: ${value}")
    val day = matchResult.groups[3]?.value
        ?: throw IllegalArgumentException("instant serialization day failed: ${value}")
    val hour = matchResult.groups[4]?.value
        ?: throw IllegalArgumentException("instant serialization hour failed: ${value}")
    val minute = matchResult.groups[5]?.value
        ?: throw IllegalArgumentException("instant serialization minute failed: ${value}")
    val seconds = matchResult.groups[6]?.value
        ?: throw IllegalArgumentException("instant serialization seconds failed: ${value}")
    return tag(0x17) { "$year$month$day$hour$minute${seconds}Z".encodeToByteArray() }
}

fun tbsCertificate(block: () -> TbsCertificate) = block().encodeToDer()

fun sigAlg(block: () -> JwsAlgorithm): ByteArray = when (val value = block()) {
    JwsAlgorithm.ES256 -> sequence { listOf(oid { "2A8648CE3D040302" }) }
    else -> throw IllegalArgumentException("sigAlg: $value")
}

private fun CryptoPublicKey.Ec.encodeToDer(): ByteArray {
    val ecKeyTag = oid { "2A8648CE3D0201" }
    val ecEncryptionNullTag = oid { "2A8648CE3D030107" }
    val content = bitString { (byteArrayOf(0x04.toByte()) + x + y) }
    return sequence { listOf(sequence { listOf(ecKeyTag, ecEncryptionNullTag) }, content) }
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
