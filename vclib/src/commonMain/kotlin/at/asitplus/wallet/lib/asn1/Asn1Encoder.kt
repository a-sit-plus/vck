package at.asitplus.wallet.lib.asn1

import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.jws.JwsAlgorithm
import at.asitplus.wallet.lib.jws.JwsExtensions.encodeToByteArray
import at.asitplus.wallet.lib.jws.TbsCertificate
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.datetime.Instant

class SequenceBuilder {

    internal val elements = mutableListOf<ByteArray>()

    fun long(block: () -> Long) = apply { elements += block().encodeToAsn1() }

    fun bitString(block: () -> ByteArray) = apply { elements += block().encodeToBitString() }

    fun oid(block: () -> String) = apply { elements += block().encodeToOid() }

    fun utf8String(block: () -> String) = apply { elements += asn1Tag(0x0c, block().encodeToByteArray()) }

    fun version(block: () -> Int) = apply { elements += asn1Tag(0xA0, block().encodeToAsn1()) }

    fun commonName(block: () -> String) = apply {
        oid { "550403" }
        utf8String { block() }
    }

    fun subjectPublicKey(block: () -> CryptoPublicKey) = apply { elements += block().encodeToAsn1() }

    fun tbsCertificate(block: () -> TbsCertificate) = apply { elements += block().encodeToDer() }

    fun sigAlg(block: () -> JwsAlgorithm) = apply { elements += block().encodeToAsn1() }

    fun utcTime(block: () -> Instant) = apply { elements += block().encodeToAsn1() }

    fun sequence(init: SequenceBuilder.() -> Unit) = apply {
        val seq = SequenceBuilder()
        seq.init()
        elements += asn1Tag(0x30, seq.elements.fold(byteArrayOf()) { acc, bytes -> acc + bytes })
    }

    fun set(init: SequenceBuilder.() -> Unit) = apply {
        val seq = SequenceBuilder()
        seq.init()
        elements += asn1Tag(0x31, seq.elements.fold(byteArrayOf()) { acc, bytes -> acc + bytes })
    }
}


fun sequence(init: SequenceBuilder.() -> Unit): ByteArray {
    val seq = SequenceBuilder()
    seq.init()
    return asn1Tag(0x30, seq.elements.fold(byteArrayOf()) { acc, bytes -> acc + bytes })
}

private fun Int.encodeToAsn1() = asn1Tag(0x02, encodeToDer())

private fun Int.encodeToDer() = encodeToByteArray().dropWhile { it == 0.toByte() }.toByteArray()

private fun Long.encodeToAsn1() = asn1Tag(0x02, encodeToDer())

private fun Long.encodeToDer() = encodeToByteArray().dropWhile { it == 0.toByte() }.toByteArray()

private fun ByteArray.encodeToBitString() = asn1Tag(0x03, (byteArrayOf(0x00) + this))

private fun asn1Tag(tag: Int, value: ByteArray) = byteArrayOf(tag.toByte()) + value.size.encodeLength() + value

private fun String.encodeToOid() = asn1Tag(0x06, decodeToByteArray(Base16()))

private fun Instant.encodeToAsn1(): ByteArray {
    val value = this.toString()
    if (value.isEmpty()) return asn1Tag(0x17, byteArrayOf())
    val matchResult = Regex("[0-9]{2}([0-9]{2})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})")
        .matchAt(value, 0)
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
    return asn1Tag(0x17, "$year$month$day$hour$minute${seconds}Z".encodeToByteArray())
}

private fun JwsAlgorithm.encodeToAsn1() = when (this) {
    JwsAlgorithm.ES256 -> sequence { oid { "2A8648CE3D040302" } }
    else -> throw IllegalArgumentException("sigAlg: $this")
}

private fun CryptoPublicKey.encodeToAsn1() = when (this) {
    is CryptoPublicKey.Ec -> sequence {
        sequence {
            oid { "2A8648CE3D0201" }
            oid { "2A8648CE3D030107" }
        }
        bitString { (byteArrayOf(0x04.toByte()) + x + y) }
    }
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
